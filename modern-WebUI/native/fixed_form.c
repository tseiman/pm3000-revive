#include "fixed_form.h"

#include "sha256.h"

#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

struct fixed_descriptor {
    const char *path;
    const char *form;
    const struct pm3000_xml_fixed_field *fields;
    const struct pm3000_xml_fixed_parameter *parameters;
    const char *const *json_keys;
    const unsigned char *json_types;
    unsigned int field_count;
    unsigned int parameter_count;
    int choice_field;
};

static const struct pm3000_xml_fixed_field help_fields[] = {
    {"applanguage", "combo", NULL},
    {"url", "RWtext", NULL}
};
static const struct pm3000_xml_fixed_parameter help_parameters[] = {
    {"applanguage", "combo", NULL},
    {"url", "RWtext", NULL}
};
static const char *const help_keys[] = {"applianceLanguage", "url"};
static const unsigned char help_types[] = {0U, 0U};

static const struct pm3000_xml_fixed_field buffering_fields[] = {
    {"local_size", "RWtext", "local"},
    {"local_segments", "RWtext", "local"},
    {"nfs_server", "RWtext", "nfs"},
    {"nfs_path", "RWtext", "nfs"},
    {"nfs_size", "RWtext", "nfs"},
    {"nfs_segments", "RWtext", "nfs"},
    {"syslog_facility", "combo", "syslog"}
};
static const struct pm3000_xml_fixed_parameter buffering_parameters[] = {
    {"local", "title", NULL},
    {"local_size", "RWtext", "local"},
    {"local_segments", "RWtext", "local"},
    {"nfs", "title", NULL},
    {"nfs_notice", "notice", "nfs"},
    {"nfs_server", "RWtext", "nfs"},
    {"nfs_path", "RWtext", "nfs"},
    {"nfs_size", "RWtext", "nfs"},
    {"nfs_segments", "RWtext", "nfs"},
    {"syslog", "title", NULL},
    {"syslog_facility", "combo", "syslog"}
};
static const char *const buffering_keys[] = {
    "localSize", "localSegments", "nfsServer", "nfsPath", "nfsSize",
    "nfsSegments", "syslogFacility"
};
static const unsigned char buffering_types[] = {1U, 1U, 0U, 0U, 1U, 1U, 0U};

static const struct fixed_descriptor help_descriptor = {
    "units.applianceSettings.help", "sessionform", help_fields, help_parameters,
    help_keys, help_types, 2U, 2U, 0
};
static const struct fixed_descriptor buffering_descriptor = {
    "units.event_notification.global_settings_databuffering",
    "global_settings_form", buffering_fields, buffering_parameters,
    buffering_keys, buffering_types, 7U, 11U, 6
};

static const struct fixed_descriptor *descriptor(pm3000_fixed_form_kind kind) {
    if (kind == PM3000_FORM_HELP_LANGUAGE) return &help_descriptor;
    if (kind == PM3000_FORM_DATA_BUFFERING) return &buffering_descriptor;
    return NULL;
}

const char *pm3000_fixed_path(pm3000_fixed_form_kind kind) {
    const struct fixed_descriptor *value = descriptor(kind);
    return value == NULL ? NULL : value->path;
}

unsigned int pm3000_fixed_field_count(pm3000_fixed_form_kind kind) {
    const struct fixed_descriptor *value = descriptor(kind);
    return value == NULL ? 0U : value->field_count;
}

static int valid_utf8_domain(const unsigned char *input, size_t length, int xml_text) {
    size_t offset = 0U;
    while (offset < length) {
        unsigned char first = input[offset++];
        unsigned int value;
        size_t remaining;
        if (first < 0x80U) {
            if (first == 0U || (xml_text && first < 0x20U)) return 0;
            continue;
        }
        if (first >= 0xc2U && first <= 0xdfU) { value = first & 0x1fU; remaining = 1U; }
        else if (first >= 0xe0U && first <= 0xefU) { value = first & 0x0fU; remaining = 2U; }
        else if (first >= 0xf0U && first <= 0xf4U) { value = first & 0x07U; remaining = 3U; }
        else return 0;
        if (offset + remaining > length) return 0;
        while (remaining-- > 0U) {
            unsigned char next = input[offset++];
            if ((next & 0xc0U) != 0x80U) return 0;
            value = (value << 6) | (next & 0x3fU);
        }
        if ((value >= 0xd800U && value <= 0xdfffU) || value > 0x10ffffU ||
            (xml_text && (value == 0xfffeU || value == 0xffffU)) ||
            value < (first <= 0xdfU ? 0x80U : first <= 0xefU ? 0x800U : 0x10000U)) return 0;
    }
    return 1;
}

static int valid_utf8(const unsigned char *input, size_t length) {
    return valid_utf8_domain(input, length, 0);
}

static int valid_xml_text(const char *input) {
    return valid_utf8_domain((const unsigned char *)input, strlen(input), 1);
}

static int decimal_value(const char *text, unsigned long minimum,
                         unsigned long maximum, unsigned long *out) {
    char *end = NULL;
    unsigned long value;
    const unsigned char *cursor = (const unsigned char *)text;
    if (*cursor == '\0' || (cursor[0] == '0' && cursor[1] != '\0')) return -1;
    while (*cursor != '\0') if (!isdigit(*cursor++)) return -1;
    errno = 0;
    value = strtoul(text, &end, 10);
    if (errno != 0 || end == text || *end != '\0' || value < minimum || value > maximum)
        return -1;
    *out = value;
    return 0;
}

static int no_space_word(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (*cursor == '\0') return 0;
    while (*cursor != '\0') {
        if (*cursor <= 0x20U || *cursor == 0x7fU) return 0;
        ++cursor;
    }
    return 1;
}

static int domain_name(const char *value) {
    size_t length = strlen(value), label = 0U, index;
    if (length == 0U || length > 253U) return 0;
    for (index = 0U; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c == '.') {
            if (label == 0U || label > 63U || value[index - 1U] == '-') return 0;
            label = 0U;
        } else {
            if (!(isalnum(c) || c == '-') || (label == 0U && c == '-')) return 0;
            ++label;
        }
    }
    return label > 0U && label <= 63U && value[length - 1U] != '-';
}

static int server_name(const char *value) {
    unsigned char address[16];
    return value[0] == '\0' || inet_pton(AF_INET, value, address) == 1 ||
           inet_pton(AF_INET6, value, address) == 1 || domain_name(value);
}

static int facility(const char *value) {
    return strlen(value) == 10U && memcmp(value, "LOG_LOCAL", 9U) == 0 &&
           value[9] >= '0' && value[9] <= '5';
}

static int validate_values(pm3000_fixed_form_kind kind,
                           char values[PM3000_FIXED_MAX_FIELDS][PM3000_FIXED_VALUE_SIZE]) {
    unsigned long ignored;
    unsigned int index, count = pm3000_fixed_field_count(kind);
    for (index = 0U; index < count; ++index)
        if (!valid_xml_text(values[index])) return -1;
    if (kind == PM3000_FORM_HELP_LANGUAGE) {
        return values[0][0] != '\0' && strlen(values[0]) <= 32U &&
               strlen(values[1]) <= 256U && no_space_word(values[1]) ? 0 : -1;
    }
    if (kind != PM3000_FORM_DATA_BUFFERING ||
        decimal_value(values[0], 0U, 2048U, &ignored) != 0 ||
        decimal_value(values[1], 1U, 9U, &ignored) != 0 ||
        strlen(values[2]) > 100U || !server_name(values[2]) ||
        strlen(values[3]) > 100U ||
        decimal_value(values[4], 0U, 99999U, &ignored) != 0 ||
        decimal_value(values[5], 0U, 99U, &ignored) != 0 || !facility(values[6])) return -1;
    return 0;
}

static void revision(pm3000_fixed_form_kind kind,
                     struct pm3000_fixed_snapshot *snapshot) {
    sha256_context context;
    unsigned char digest[32];
    static const char hex[] = "0123456789abcdef";
    unsigned int index;
    unsigned char marker = (unsigned char)kind;
    sha256_init(&context);
    sha256_update(&context, &marker, 1U);
    for (index = 0U; index < pm3000_fixed_field_count(kind); ++index) {
        sha256_update(&context, snapshot->form.values[index],
                      strlen(snapshot->form.values[index]) + 1U);
    }
    for (index = 0U; index < snapshot->form.choice_count; ++index)
        sha256_update(&context, snapshot->form.choices[index],
                      strlen(snapshot->form.choices[index]) + 1U);
    sha256_final(&context, digest);
    snapshot->revision[0] = '"';
    for (index = 0U; index < 32U; ++index) {
        snapshot->revision[1U + index * 2U] = hex[digest[index] >> 4];
        snapshot->revision[2U + index * 2U] = hex[digest[index] & 15U];
    }
    snapshot->revision[65] = '"';
    snapshot->revision[66] = '\0';
    memset(digest, 0, sizeof(digest));
}

int pm3000_fixed_parse_backend(pm3000_fixed_form_kind kind,
                               const unsigned char *xml, size_t length,
                               struct pm3000_fixed_snapshot *out) {
    const struct fixed_descriptor *value = descriptor(kind);
    unsigned int index;
    if (value == NULL || out == NULL ||
        pm3000_xml_fixed_form(xml, length, value->path, value->form,
                              value->fields, value->field_count,
                              value->parameters, value->parameter_count,
                              value->choice_field, &out->form) != 0 ||
        validate_values(kind, out->form.values) != 0) return -1;
    if (kind == PM3000_FORM_HELP_LANGUAGE) {
        if (!pm3000_fixed_language_allowed(out, out->form.values[0])) return -1;
        for (index = 0U; index < out->form.choice_count; ++index)
            if (!valid_xml_text(out->form.choices[index])) return -1;
    } else {
        if (out->form.choice_count != 6U) return -1;
        for (index = 0U; index < 6U; ++index) {
            char expected[11];
            (void)snprintf(expected, sizeof(expected), "LOG_LOCAL%u", index);
            if (strcmp(out->form.choices[index], expected) != 0) return -1;
        }
    }
    revision(kind, out);
    return 0;
}

struct json_cursor { const unsigned char *data; size_t length; size_t offset; };

static void json_space(struct json_cursor *cursor) {
    while (cursor->offset < cursor->length &&
           (cursor->data[cursor->offset] == ' ' || cursor->data[cursor->offset] == '\t' ||
            cursor->data[cursor->offset] == '\r' || cursor->data[cursor->offset] == '\n'))
        ++cursor->offset;
}

static int json_char(struct json_cursor *cursor, unsigned char expected) {
    json_space(cursor);
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != expected) return -1;
    return 0;
}

static int hex_value(unsigned char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static int append_utf8(char *output, size_t *used, size_t capacity, unsigned int codepoint) {
    unsigned char encoded[4]; size_t amount;
    if (codepoint == 0U || (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU)
        return -1;
    if (codepoint < 0x80U) { encoded[0] = (unsigned char)codepoint; amount = 1U; }
    else if (codepoint < 0x800U) { encoded[0] = 0xc0U | (codepoint >> 6); encoded[1] = 0x80U | (codepoint & 63U); amount = 2U; }
    else if (codepoint < 0x10000U) { encoded[0] = 0xe0U | (codepoint >> 12); encoded[1] = 0x80U | ((codepoint >> 6) & 63U); encoded[2] = 0x80U | (codepoint & 63U); amount = 3U; }
    else { encoded[0] = 0xf0U | (codepoint >> 18); encoded[1] = 0x80U | ((codepoint >> 12) & 63U); encoded[2] = 0x80U | ((codepoint >> 6) & 63U); encoded[3] = 0x80U | (codepoint & 63U); amount = 4U; }
    if (*used + amount >= capacity) return -1;
    memcpy(output + *used, encoded, amount); *used += amount; output[*used] = '\0';
    return 0;
}

static int unicode_escape(struct json_cursor *cursor, unsigned int *codepoint) {
    unsigned int value = 0U, index;
    for (index = 0U; index < 4U; ++index) {
        int part;
        if (cursor->offset >= cursor->length || (part = hex_value(cursor->data[cursor->offset++])) < 0) return -1;
        value = value * 16U + (unsigned int)part;
    }
    if (value >= 0xd800U && value <= 0xdbffU) {
        unsigned int low = 0U;
        if (cursor->offset + 6U > cursor->length || cursor->data[cursor->offset++] != '\\' ||
            cursor->data[cursor->offset++] != 'u') return -1;
        for (index = 0U; index < 4U; ++index) {
            int part = hex_value(cursor->data[cursor->offset++]); if (part < 0) return -1;
            low = low * 16U + (unsigned int)part;
        }
        if (low < 0xdc00U || low > 0xdfffU) return -1;
        value = 0x10000U + ((value - 0xd800U) << 10) + low - 0xdc00U;
    } else if (value >= 0xdc00U && value <= 0xdfffU) return -1;
    *codepoint = value;
    return 0;
}

static int json_string(struct json_cursor *cursor, char *output, size_t capacity) {
    size_t used = 0U;
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != '"') return -1;
    output[0] = '\0';
    while (cursor->offset < cursor->length) {
        unsigned char c = cursor->data[cursor->offset++];
        if (c == '"') return valid_utf8((const unsigned char *)output, used) ? 0 : -1;
        if (c < 0x20U) return -1;
        if (c == '\\') {
            unsigned int codepoint;
            if (cursor->offset >= cursor->length) return -1;
            c = cursor->data[cursor->offset++];
            if (c == 'u') { if (unicode_escape(cursor, &codepoint) != 0 || append_utf8(output, &used, capacity, codepoint) != 0) return -1; continue; }
            if (c == '"' || c == '\\' || c == '/') codepoint = c;
            else if (c == 'b') codepoint = '\b'; else if (c == 'f') codepoint = '\f';
            else if (c == 'n') codepoint = '\n'; else if (c == 'r') codepoint = '\r'; else if (c == 't') codepoint = '\t'; else return -1;
            if (codepoint < 0x20U || append_utf8(output, &used, capacity, codepoint) != 0) return -1;
        } else {
            if (used + 1U >= capacity) return -1;
            output[used++] = (char)c; output[used] = '\0';
        }
    }
    return -1;
}

static int json_integer(struct json_cursor *cursor, char *output, size_t capacity) {
    size_t start = cursor->offset, amount;
    if (cursor->offset < cursor->length && cursor->data[cursor->offset] == '-') ++cursor->offset;
    if (cursor->offset >= cursor->length) return -1;
    if (cursor->data[cursor->offset] == '0') ++cursor->offset;
    else {
        if (cursor->data[cursor->offset] < '1' || cursor->data[cursor->offset] > '9') return -1;
        while (cursor->offset < cursor->length && isdigit(cursor->data[cursor->offset])) ++cursor->offset;
    }
    amount = cursor->offset - start;
    if (amount == 0U || amount >= capacity) return -1;
    memcpy(output, cursor->data + start, amount); output[amount] = '\0';
    return 0;
}

int pm3000_fixed_parse_request(pm3000_fixed_form_kind kind,
                               const unsigned char *json, size_t length,
                               struct pm3000_fixed_input *out) {
    const struct fixed_descriptor *value = descriptor(kind);
    struct json_cursor cursor = {json, length, 0U};
    unsigned int seen[PM3000_FIXED_MAX_FIELDS] = {0}, members = 0U;
    if (value == NULL || out == NULL || length == 0U || !valid_utf8(json, length) ||
        json_char(&cursor, '{') != 0) return -1;
    memset(out, 0, sizeof(*out));
    for (;;) {
        char key[64]; unsigned int index;
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') { ++cursor.offset; break; }
        if (members++ > 0U && json_char(&cursor, ',') != 0) return -1;
        json_space(&cursor);
        if (json_string(&cursor, key, sizeof(key)) != 0 || json_char(&cursor, ':') != 0) return -1;
        for (index = 0U; index < value->field_count; ++index)
            if (strcmp(key, value->json_keys[index]) == 0) break;
        if (index == value->field_count || seen[index]++) return -1;
        json_space(&cursor);
        if ((value->json_types[index] == 0U && json_string(&cursor, out->values[index], sizeof(out->values[index])) != 0) ||
            (value->json_types[index] == 1U && json_integer(&cursor, out->values[index], sizeof(out->values[index])) != 0)) return -1;
    }
    json_space(&cursor);
    if (cursor.offset != cursor.length) return -1;
    for (members = 0U; members < value->field_count; ++members) if (seen[members] != 1U) return -1;
    return validate_values(kind, out->values);
}

int pm3000_fixed_language_allowed(const struct pm3000_fixed_snapshot *snapshot,
                                   const char *language) {
    unsigned int index;
    if (snapshot == NULL || language == NULL || language[0] == '\0' || strlen(language) > 32U) return 0;
    for (index = 0U; index < snapshot->form.choice_count; ++index)
        if (strcmp(snapshot->form.choices[index], language) == 0) return 1;
    return 0;
}

int pm3000_fixed_values_match(pm3000_fixed_form_kind kind,
                              const struct pm3000_fixed_snapshot *snapshot,
                              const struct pm3000_fixed_input *input) {
    unsigned int index, count = pm3000_fixed_field_count(kind);
    if (snapshot == NULL || input == NULL || count == 0U) return 0;
    for (index = 0U; index < count; ++index)
        if (strcmp(snapshot->form.values[index], input->values[index]) != 0) return 0;
    return 1;
}

static int xml_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0U;
    while (*input != '\0') {
        const char *replacement = NULL; size_t amount;
        if (*input == '&') replacement = "&amp;"; else if (*input == '<') replacement = "&lt;";
        else if (*input == '>') replacement = "&gt;"; else if (*input == '"') replacement = "&quot;";
        else if (*input == '\'') replacement = "&apos;";
        if (replacement != NULL) { amount = strlen(replacement); if (used + amount >= capacity) return -1; memcpy(output + used, replacement, amount); used += amount; }
        else { if (used + 1U >= capacity) return -1; output[used++] = *input; }
        ++input;
    }
    output[used] = '\0'; return 0;
}

int pm3000_fixed_serialize(pm3000_fixed_form_kind kind,
                           const struct pm3000_fixed_input *input,
                           char *output, size_t capacity) {
    const struct fixed_descriptor *value = descriptor(kind);
    char escaped[PM3000_FIXED_MAX_FIELDS][PM3000_FIXED_VALUE_SIZE * 6U];
    size_t used = 0U; unsigned int index;
    int amount;
    if (value == NULL || input == NULL || output == NULL || capacity == 0U ||
        validate_values(kind, (char (*)[PM3000_FIXED_VALUE_SIZE])input->values) != 0) return -1;
    for (index = 0U; index < value->field_count; ++index)
        if (xml_escape(input->values[index], escaped[index], sizeof(escaped[index])) != 0) return -1;
    amount = snprintf(output, capacity, "<section structure=\"form\">");
    if (amount < 0 || (size_t)amount >= capacity) return -1;
    used = (size_t)amount;
    for (index = 0U; index < value->field_count; ++index) {
        amount = snprintf(output + used, capacity - used,
                          "<parameter id=\"%s\" structure=\"%s\"><value>%s</value></parameter>",
                          value->fields[index].id, value->fields[index].structure, escaped[index]);
        if (amount < 0 || (size_t)amount >= capacity - used) return -1;
        used += (size_t)amount;
    }
    amount = snprintf(output + used, capacity - used, "</section>");
    return amount < 0 || (size_t)amount >= capacity - used ? -1 : 0;
}
