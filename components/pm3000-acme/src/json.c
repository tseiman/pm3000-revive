#include "pm3000_acme_json.h"

struct json_parser {
    struct pm3000_acme_json_document *document;
    unsigned int offset;
    int error;
};

static int valid_utf8(const unsigned char *input, unsigned int length)
{
    unsigned int offset = 0U;
    while (offset < length) {
        unsigned char first = input[offset++];
        unsigned int value;
        unsigned int remaining;
        if (first < 0x80U) continue;
        if (first >= 0xc2U && first <= 0xdfU) {
            value = first & 0x1fU;
            remaining = 1U;
        } else if (first >= 0xe0U && first <= 0xefU) {
            value = first & 0x0fU;
            remaining = 2U;
        } else if (first >= 0xf0U && first <= 0xf4U) {
            value = first & 0x07U;
            remaining = 3U;
        } else {
            return 0;
        }
        if (offset + remaining > length) return 0;
        while (remaining-- > 0U) {
            unsigned char next = input[offset++];
            if ((next & 0xc0U) != 0x80U) return 0;
            value = (value << 6) | (unsigned int)(next & 0x3fU);
        }
        if ((value >= 0xd800U && value <= 0xdfffU) || value > 0x10ffffU ||
            value < (first <= 0xdfU ? 0x80U :
                     first <= 0xefU ? 0x800U : 0x10000U)) {
            return 0;
        }
    }
    return 1;
}

static void skip_space(struct json_parser *parser)
{
    const struct pm3000_acme_json_document *document = parser->document;
    while (parser->offset < document->length) {
        unsigned char value = document->data[parser->offset];
        if (value != ' ' && value != '\t' && value != '\r' && value != '\n') {
            break;
        }
        ++parser->offset;
    }
}

static int new_token(struct json_parser *parser, unsigned char type, int parent)
{
    struct pm3000_acme_json_document *document = parser->document;
    struct pm3000_acme_json_token *token;
    int index;
    if (document->token_count >= PM3000_ACME_JSON_MAX_TOKENS) {
        parser->error = PM3000_ACME_JSON_LIMIT;
        return -1;
    }
    index = (int)document->token_count++;
    token = &document->tokens[index];
    token->start = parser->offset;
    token->end = parser->offset;
    token->parent = parent;
    token->count = 0U;
    token->type = type;
    return index;
}

static int hex_value(unsigned char value)
{
    if (value >= '0' && value <= '9') return (int)(value - '0');
    if (value >= 'a' && value <= 'f') return (int)(value - 'a') + 10;
    if (value >= 'A' && value <= 'F') return (int)(value - 'A') + 10;
    return -1;
}

static int read_hex4(const unsigned char *data, unsigned int length,
                     unsigned int *offset, unsigned int *value)
{
    unsigned int result = 0U;
    unsigned int index;
    for (index = 0U; index < 4U; ++index) {
        int part;
        if (*offset >= length || (part = hex_value(data[(*offset)++])) < 0) {
            return 0;
        }
        result = result * 16U + (unsigned int)part;
    }
    *value = result;
    return 1;
}

static int read_unicode_escape(const unsigned char *data, unsigned int length,
                               unsigned int *offset, unsigned int *codepoint)
{
    unsigned int value;
    if (!read_hex4(data, length, offset, &value)) return 0;
    if (value >= 0xd800U && value <= 0xdbffU) {
        unsigned int low;
        if (*offset + 2U > length || data[(*offset)++] != '\\' ||
            data[(*offset)++] != 'u' ||
            !read_hex4(data, length, offset, &low) ||
            low < 0xdc00U || low > 0xdfffU) {
            return 0;
        }
        value = 0x10000U + ((value - 0xd800U) << 10) + low - 0xdc00U;
    } else if (value >= 0xdc00U && value <= 0xdfffU) {
        return 0;
    }
    *codepoint = value;
    return 1;
}

static int parse_string(struct json_parser *parser, int parent)
{
    struct pm3000_acme_json_document *document = parser->document;
    struct pm3000_acme_json_token *token;
    int token_index;
    if (parser->offset >= document->length ||
        document->data[parser->offset] != '"') {
        parser->error = PM3000_ACME_JSON_INVALID;
        return -1;
    }
    ++parser->offset;
    token_index = new_token(parser, PM3000_ACME_JSON_STRING, parent);
    if (token_index < 0) return -1;
    token = &document->tokens[token_index];
    token->start = parser->offset;
    while (parser->offset < document->length) {
        unsigned char value = document->data[parser->offset++];
        if (value == '"') {
            token->end = parser->offset - 1U;
            return token_index;
        }
        if (value < 0x20U) {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
        if (value == '\\') {
            unsigned int codepoint;
            if (parser->offset >= document->length) {
                parser->error = PM3000_ACME_JSON_INVALID;
                return -1;
            }
            value = document->data[parser->offset++];
            if (value == 'u') {
                if (!read_unicode_escape(document->data, document->length,
                                         &parser->offset, &codepoint) ||
                    codepoint == 0U) {
                    parser->error = PM3000_ACME_JSON_INVALID;
                    return -1;
                }
            } else if (value != '"' && value != '\\' && value != '/' &&
                       value != 'b' && value != 'f' && value != 'n' &&
                       value != 'r' && value != 't') {
                parser->error = PM3000_ACME_JSON_INVALID;
                return -1;
            }
        }
    }
    parser->error = PM3000_ACME_JSON_INVALID;
    return -1;
}

static int append_byte(char *output, unsigned int *used,
                       unsigned int capacity, unsigned char value)
{
    if (*used + 1U >= capacity) return PM3000_ACME_JSON_OUTPUT_TOO_SMALL;
    output[(*used)++] = (char)value;
    output[*used] = '\0';
    return PM3000_ACME_JSON_OK;
}

static int append_codepoint(char *output, unsigned int *used,
                            unsigned int capacity, unsigned int codepoint)
{
    if (codepoint == 0U || codepoint > 0x10ffffU ||
        (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
        return PM3000_ACME_JSON_INVALID;
    }
    if (codepoint < 0x80U) {
        return append_byte(output, used, capacity, (unsigned char)codepoint);
    }
    if (codepoint < 0x800U) {
        if (append_byte(output, used, capacity,
                        (unsigned char)(0xc0U | (codepoint >> 6))) != 0 ||
            append_byte(output, used, capacity,
                        (unsigned char)(0x80U | (codepoint & 63U))) != 0) {
            return PM3000_ACME_JSON_OUTPUT_TOO_SMALL;
        }
        return PM3000_ACME_JSON_OK;
    }
    if (codepoint < 0x10000U) {
        if (append_byte(output, used, capacity,
                        (unsigned char)(0xe0U | (codepoint >> 12))) != 0 ||
            append_byte(output, used, capacity,
                        (unsigned char)(0x80U | ((codepoint >> 6) & 63U))) != 0 ||
            append_byte(output, used, capacity,
                        (unsigned char)(0x80U | (codepoint & 63U))) != 0) {
            return PM3000_ACME_JSON_OUTPUT_TOO_SMALL;
        }
        return PM3000_ACME_JSON_OK;
    }
    if (append_byte(output, used, capacity,
                    (unsigned char)(0xf0U | (codepoint >> 18))) != 0 ||
        append_byte(output, used, capacity,
                    (unsigned char)(0x80U | ((codepoint >> 12) & 63U))) != 0 ||
        append_byte(output, used, capacity,
                    (unsigned char)(0x80U | ((codepoint >> 6) & 63U))) != 0 ||
        append_byte(output, used, capacity,
                    (unsigned char)(0x80U | (codepoint & 63U))) != 0) {
        return PM3000_ACME_JSON_OUTPUT_TOO_SMALL;
    }
    return PM3000_ACME_JSON_OK;
}

int pm3000_acme_json_string_copy(const struct pm3000_acme_json_document *document,
                                 int string_token, char *output,
                                 unsigned int output_capacity)
{
    const struct pm3000_acme_json_token *token;
    unsigned int offset;
    unsigned int used = 0U;
    if (output == (char *)0 || output_capacity == 0U) {
        return PM3000_ACME_JSON_INVALID;
    }
    output[0] = '\0';
    if (document == (const struct pm3000_acme_json_document *)0 ||
        string_token < 0 || (unsigned int)string_token >= document->token_count) {
        return PM3000_ACME_JSON_INVALID;
    }
    token = &document->tokens[string_token];
    if (token->type != PM3000_ACME_JSON_STRING) return PM3000_ACME_JSON_TYPE;
    offset = token->start;
    while (offset < token->end) {
        unsigned char value = document->data[offset++];
        int result;
        if (value != '\\') {
            result = append_byte(output, &used, output_capacity, value);
        } else {
            unsigned int codepoint;
            if (offset >= token->end) return PM3000_ACME_JSON_INVALID;
            value = document->data[offset++];
            if (value == 'u') {
                if (!read_unicode_escape(document->data, token->end, &offset,
                                         &codepoint)) {
                    return PM3000_ACME_JSON_INVALID;
                }
            } else if (value == '"' || value == '\\' || value == '/') {
                codepoint = value;
            } else if (value == 'b') {
                codepoint = '\b';
            } else if (value == 'f') {
                codepoint = '\f';
            } else if (value == 'n') {
                codepoint = '\n';
            } else if (value == 'r') {
                codepoint = '\r';
            } else if (value == 't') {
                codepoint = '\t';
            } else {
                return PM3000_ACME_JSON_INVALID;
            }
            result = append_codepoint(output, &used, output_capacity, codepoint);
        }
        if (result != PM3000_ACME_JSON_OK) {
            output[0] = '\0';
            return result;
        }
    }
    return PM3000_ACME_JSON_OK;
}

static int decoded_key_equal(const struct pm3000_acme_json_document *document,
                             int left, int right)
{
    char left_text[PM3000_ACME_JSON_KEY_MAX + 1U];
    char right_text[PM3000_ACME_JSON_KEY_MAX + 1U];
    unsigned int index = 0U;
    if (pm3000_acme_json_string_copy(document, left, left_text,
                                     sizeof(left_text)) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(document, right, right_text,
                                     sizeof(right_text)) != PM3000_ACME_JSON_OK) {
        return -1;
    }
    while (left_text[index] != '\0' && right_text[index] != '\0') {
        if (left_text[index] != right_text[index]) return 0;
        ++index;
    }
    return left_text[index] == right_text[index] ? 1 : 0;
}

static int parse_value(struct json_parser *parser, int parent,
                       unsigned int depth);

static int parse_object(struct json_parser *parser, int parent,
                        unsigned int depth)
{
    struct pm3000_acme_json_document *document = parser->document;
    int key_tokens[PM3000_ACME_JSON_MAX_MEMBERS];
    int object_index;
    unsigned int member_count = 0U;
    if (depth >= PM3000_ACME_JSON_MAX_DEPTH) {
        parser->error = PM3000_ACME_JSON_LIMIT;
        return -1;
    }
    object_index = new_token(parser, PM3000_ACME_JSON_OBJECT, parent);
    if (object_index < 0) return -1;
    ++parser->offset;
    skip_space(parser);
    if (parser->offset < document->length &&
        document->data[parser->offset] == '}') {
        ++parser->offset;
        document->tokens[object_index].end = parser->offset;
        return object_index;
    }
    for (;;) {
        int key_index;
        unsigned int previous;
        if (member_count >= PM3000_ACME_JSON_MAX_MEMBERS) {
            parser->error = PM3000_ACME_JSON_LIMIT;
            return -1;
        }
        skip_space(parser);
        key_index = parse_string(parser, object_index);
        if (key_index < 0) return -1;
        {
            char key[PM3000_ACME_JSON_KEY_MAX + 1U];
            if (pm3000_acme_json_string_copy(document, key_index, key,
                                             sizeof(key)) != PM3000_ACME_JSON_OK) {
                parser->error = PM3000_ACME_JSON_LIMIT;
                return -1;
            }
        }
        for (previous = 0U; previous < member_count; ++previous) {
            int equal = decoded_key_equal(document, key_tokens[previous], key_index);
            if (equal != 0) {
                parser->error = equal > 0 ? PM3000_ACME_JSON_INVALID :
                                            PM3000_ACME_JSON_LIMIT;
                return -1;
            }
        }
        key_tokens[member_count] = key_index;
        skip_space(parser);
        if (parser->offset >= document->length ||
            document->data[parser->offset++] != ':') {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
        if (parse_value(parser, object_index, depth + 1U) < 0) return -1;
        ++member_count;
        skip_space(parser);
        if (parser->offset >= document->length) {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
        if (document->data[parser->offset] == '}') {
            ++parser->offset;
            document->tokens[object_index].count = member_count;
            document->tokens[object_index].end = parser->offset;
            return object_index;
        }
        if (document->data[parser->offset++] != ',') {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
    }
}

static int parse_array(struct json_parser *parser, int parent,
                       unsigned int depth)
{
    struct pm3000_acme_json_document *document = parser->document;
    int array_index;
    unsigned int item_count = 0U;
    if (depth >= PM3000_ACME_JSON_MAX_DEPTH) {
        parser->error = PM3000_ACME_JSON_LIMIT;
        return -1;
    }
    array_index = new_token(parser, PM3000_ACME_JSON_ARRAY, parent);
    if (array_index < 0) return -1;
    ++parser->offset;
    skip_space(parser);
    if (parser->offset < document->length &&
        document->data[parser->offset] == ']') {
        ++parser->offset;
        document->tokens[array_index].end = parser->offset;
        return array_index;
    }
    for (;;) {
        if (item_count >= PM3000_ACME_JSON_MAX_MEMBERS) {
            parser->error = PM3000_ACME_JSON_LIMIT;
            return -1;
        }
        if (parse_value(parser, array_index, depth + 1U) < 0) return -1;
        ++item_count;
        skip_space(parser);
        if (parser->offset >= document->length) {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
        if (document->data[parser->offset] == ']') {
            ++parser->offset;
            document->tokens[array_index].count = item_count;
            document->tokens[array_index].end = parser->offset;
            return array_index;
        }
        if (document->data[parser->offset++] != ',') {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
    }
}

static int parse_number(struct json_parser *parser, int parent)
{
    struct pm3000_acme_json_document *document = parser->document;
    int token_index = new_token(parser, PM3000_ACME_JSON_NUMBER, parent);
    if (token_index < 0) return -1;
    document->tokens[token_index].start = parser->offset;
    if (parser->offset < document->length &&
        document->data[parser->offset] == '-') {
        ++parser->offset;
    }
    if (parser->offset >= document->length) goto rejected;
    if (document->data[parser->offset] == '0') {
        ++parser->offset;
        if (parser->offset < document->length &&
            document->data[parser->offset] >= '0' &&
            document->data[parser->offset] <= '9') goto rejected;
    } else {
        if (document->data[parser->offset] < '1' ||
            document->data[parser->offset] > '9') goto rejected;
        while (parser->offset < document->length &&
               document->data[parser->offset] >= '0' &&
               document->data[parser->offset] <= '9') ++parser->offset;
    }
    if (parser->offset < document->length &&
        document->data[parser->offset] == '.') {
        ++parser->offset;
        if (parser->offset >= document->length ||
            document->data[parser->offset] < '0' ||
            document->data[parser->offset] > '9') goto rejected;
        while (parser->offset < document->length &&
               document->data[parser->offset] >= '0' &&
               document->data[parser->offset] <= '9') ++parser->offset;
    }
    if (parser->offset < document->length &&
        (document->data[parser->offset] == 'e' ||
         document->data[parser->offset] == 'E')) {
        ++parser->offset;
        if (parser->offset < document->length &&
            (document->data[parser->offset] == '+' ||
             document->data[parser->offset] == '-')) ++parser->offset;
        if (parser->offset >= document->length ||
            document->data[parser->offset] < '0' ||
            document->data[parser->offset] > '9') goto rejected;
        while (parser->offset < document->length &&
               document->data[parser->offset] >= '0' &&
               document->data[parser->offset] <= '9') ++parser->offset;
    }
    document->tokens[token_index].end = parser->offset;
    return token_index;

rejected:
    parser->error = PM3000_ACME_JSON_INVALID;
    return -1;
}

static int parse_literal(struct json_parser *parser, int parent,
                         const char *literal, unsigned int length,
                         unsigned char type)
{
    struct pm3000_acme_json_document *document = parser->document;
    unsigned int index;
    int token_index;
    if (parser->offset + length > document->length) {
        parser->error = PM3000_ACME_JSON_INVALID;
        return -1;
    }
    for (index = 0U; index < length; ++index) {
        if (document->data[parser->offset + index] !=
            (unsigned char)literal[index]) {
            parser->error = PM3000_ACME_JSON_INVALID;
            return -1;
        }
    }
    token_index = new_token(parser, type, parent);
    if (token_index < 0) return -1;
    document->tokens[token_index].start = parser->offset;
    parser->offset += length;
    document->tokens[token_index].end = parser->offset;
    return token_index;
}

static int parse_value(struct json_parser *parser, int parent,
                       unsigned int depth)
{
    const struct pm3000_acme_json_document *document = parser->document;
    skip_space(parser);
    if (parser->offset >= document->length) {
        parser->error = PM3000_ACME_JSON_INVALID;
        return -1;
    }
    switch (document->data[parser->offset]) {
    case '{': return parse_object(parser, parent, depth);
    case '[': return parse_array(parser, parent, depth);
    case '"': return parse_string(parser, parent);
    case 't': return parse_literal(parser, parent, "true", 4U,
                                   PM3000_ACME_JSON_TRUE);
    case 'f': return parse_literal(parser, parent, "false", 5U,
                                   PM3000_ACME_JSON_FALSE);
    case 'n': return parse_literal(parser, parent, "null", 4U,
                                   PM3000_ACME_JSON_NULL);
    default: return parse_number(parser, parent);
    }
}

int pm3000_acme_json_parse(const unsigned char *data, unsigned int length,
                           struct pm3000_acme_json_document *document)
{
    struct json_parser parser;
    if (document == (struct pm3000_acme_json_document *)0) {
        return PM3000_ACME_JSON_INVALID;
    }
    document->data = data;
    document->length = length;
    document->token_count = 0U;
    if (data == (const unsigned char *)0 || length == 0U ||
        length > PM3000_ACME_JSON_MAX_BYTES || !valid_utf8(data, length)) {
        return length > PM3000_ACME_JSON_MAX_BYTES ? PM3000_ACME_JSON_LIMIT :
                                                     PM3000_ACME_JSON_INVALID;
    }
    parser.document = document;
    parser.offset = 0U;
    parser.error = PM3000_ACME_JSON_INVALID;
    if (parse_value(&parser, -1, 0U) != 0) {
        document->token_count = 0U;
        return parser.error;
    }
    skip_space(&parser);
    if (parser.offset != length) {
        document->token_count = 0U;
        return PM3000_ACME_JSON_INVALID;
    }
    return PM3000_ACME_JSON_OK;
}

static int ascii_equal(const char *left, const char *right)
{
    unsigned int index = 0U;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

int pm3000_acme_json_object_get(const struct pm3000_acme_json_document *document,
                                int object_token, const char *key,
                                int *value_token)
{
    unsigned int index;
    if (document == (const struct pm3000_acme_json_document *)0 ||
        key == (const char *)0 || value_token == (int *)0 || object_token < 0 ||
        (unsigned int)object_token >= document->token_count) {
        return PM3000_ACME_JSON_INVALID;
    }
    if (document->tokens[object_token].type != PM3000_ACME_JSON_OBJECT) {
        return PM3000_ACME_JSON_TYPE;
    }
    for (index = (unsigned int)object_token + 1U;
         index + 1U < document->token_count; ++index) {
        char decoded[PM3000_ACME_JSON_KEY_MAX + 1U];
        if (document->tokens[index].parent != object_token ||
            document->tokens[index].type != PM3000_ACME_JSON_STRING) continue;
        if (pm3000_acme_json_string_copy(document, (int)index, decoded,
                                         sizeof(decoded)) != PM3000_ACME_JSON_OK) {
            return PM3000_ACME_JSON_INVALID;
        }
        if (ascii_equal(decoded, key)) {
            *value_token = (int)index + 1;
            return PM3000_ACME_JSON_OK;
        }
        ++index;
    }
    return PM3000_ACME_JSON_NOT_FOUND;
}

int pm3000_acme_json_array_length(const struct pm3000_acme_json_document *document,
                                  int array_token, unsigned int *length)
{
    if (document == (const struct pm3000_acme_json_document *)0 ||
        length == (unsigned int *)0 || array_token < 0 ||
        (unsigned int)array_token >= document->token_count) {
        return PM3000_ACME_JSON_INVALID;
    }
    if (document->tokens[array_token].type != PM3000_ACME_JSON_ARRAY) {
        return PM3000_ACME_JSON_TYPE;
    }
    *length = document->tokens[array_token].count;
    return PM3000_ACME_JSON_OK;
}

int pm3000_acme_json_array_get(const struct pm3000_acme_json_document *document,
                               int array_token, unsigned int wanted,
                               int *value_token)
{
    unsigned int index;
    unsigned int found = 0U;
    if (document == (const struct pm3000_acme_json_document *)0 ||
        value_token == (int *)0 || array_token < 0 ||
        (unsigned int)array_token >= document->token_count) {
        return PM3000_ACME_JSON_INVALID;
    }
    if (document->tokens[array_token].type != PM3000_ACME_JSON_ARRAY) {
        return PM3000_ACME_JSON_TYPE;
    }
    for (index = (unsigned int)array_token + 1U;
         index < document->token_count; ++index) {
        if (document->tokens[index].parent != array_token) continue;
        if (found++ == wanted) {
            *value_token = (int)index;
            return PM3000_ACME_JSON_OK;
        }
    }
    return PM3000_ACME_JSON_NOT_FOUND;
}
