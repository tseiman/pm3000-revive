#define _POSIX_C_SOURCE 200809L

#include "projector.h"
#include "identifiers.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_XML_BYTES (1024UL * 1024UL)
#define MAX_DEPTH 32U
#define MAX_OUTLETS 256U
#define MAX_PDUS 64U
#define MAX_NAME_BYTES 128U
#define MAX_IDENTITY_BYTES 255U
#define MAX_TEXT_BYTES 255U
#define MAX_ATTRIBUTES 24U

struct row_value {
    char identity[MAX_IDENTITY_BYTES + 1U];
    char pdu_identity[MAX_IDENTITY_BYTES + 1U];
    char name[MAX_NAME_BYTES + 1U];
    char port[16];
    char type[32];
    char status[32];
    unsigned int seen_name;
    unsigned int seen_port;
    unsigned int seen_type;
    unsigned int seen_status;
    unsigned int seen_action;
    unsigned int unexpected;
    char pdu_name[MAX_NAME_BYTES + 1U];
    char pdu_vendor[MAX_NAME_BYTES + 1U];
    char pdu_model[MAX_NAME_BYTES + 1U];
    char pdu_pos[16];
    char pdu_status[32];
    char pdu_current[32];
    char pdu_power[32];
    char pdu_alarm[64];
    unsigned int seen_pdu_name, seen_pdu_vendor, seen_pdu_model, seen_pdu_pos;
    unsigned int seen_pdu_status, seen_pdu_current, seen_pdu_power, seen_pdu_alarm;
};

struct outlet {
    char identity[MAX_IDENTITY_BYTES + 1U];
    char pdu_identity[MAX_IDENTITY_BYTES + 1U];
    char name[MAX_NAME_BYTES + 1U];
    char id[PM3000_ID_LENGTH + 1U];
    char pdu_id[PM3000_ID_LENGTH + 1U];
    unsigned int position;
    const char *state;
};

struct pdu {
    char identity[MAX_IDENTITY_BYTES + 1U];
    char id[PM3000_ID_LENGTH + 1U];
    char name[MAX_NAME_BYTES + 1U];
    char vendor[MAX_NAME_BYTES + 1U];
    char model[MAX_NAME_BYTES + 1U];
    unsigned int position, outlets_on, outlet_count;
    char current[32], power[32], alarm[64];
};

struct frame {
    char name[32];
    char id[MAX_IDENTITY_BYTES + 1U];
    char structure[32];
    char parameter_id[32];
    char text[MAX_TEXT_BYTES + 1U];
    size_t text_length;
    struct row_value row;
};

struct parser {
    const unsigned char *input;
    size_t length;
    size_t offset;
    struct frame stack[MAX_DEPTH];
    size_t depth;
    struct outlet outlets[MAX_OUTLETS];
    size_t outlet_count;
    struct pdu pdus[MAX_PDUS];
    size_t pdu_count;
    unsigned int root_count;
    unsigned int xml_declarations;
    unsigned int vendor_stylesheets;
    unsigned int action_count;
    unsigned int path_count;
    unsigned int topology_count;
    unsigned int pdu_table_count;
    unsigned int pdu_on, pdu_off, pdu_cycle;
    int mode;
    char action[32];
    char path[64];
    char error[160];
};

static void fail(struct parser *parser, const char *format, ...) {
    va_list arguments;
    if (parser->error[0] != '\0') return;
    va_start(arguments, format);
    (void)vsnprintf(parser->error, sizeof(parser->error), format, arguments);
    va_end(arguments);
}

static int valid_utf8(const unsigned char *text, size_t length) {
    size_t offset = 0;
    while (offset < length) {
        unsigned char first = text[offset++];
        uint32_t value;
        size_t remaining;
        if (first < 0x80U) {
            if (first == 0U) return 0;
            continue;
        }
        if (first >= 0xc2U && first <= 0xdfU) { value = first & 0x1fU; remaining = 1; }
        else if (first >= 0xe0U && first <= 0xefU) { value = first & 0x0fU; remaining = 2; }
        else if (first >= 0xf0U && first <= 0xf4U) { value = first & 0x07U; remaining = 3; }
        else return 0;
        if (offset + remaining > length) return 0;
        while (remaining-- > 0U) {
            unsigned char next = text[offset++];
            if ((next & 0xc0U) != 0x80U) return 0;
            value = (value << 6) | (next & 0x3fU);
        }
        if ((value >= 0xd800U && value <= 0xdfffU) || value > 0x10ffffU ||
            value < (first <= 0xdfU ? 0x80U : first <= 0xefU ? 0x800U : 0x10000U)) return 0;
    }
    return 1;
}

static int known_element(const char *name) {
    static const char *const names[] = {
        "avtrans", "identity", "sid", "alarm", "action", "agents", "src", "dest",
        "paths", "path", "pathvar", "payload", "section", "controls", "control",
        "script", "array", "parameter", "value"
    };
    size_t index;
    for (index = 0; index < sizeof(names) / sizeof(names[0]); ++index) {
        if (strcmp(name, names[index]) == 0) return 1;
    }
    return 0;
}

static void skip_space(struct parser *parser) {
    while (parser->offset < parser->length && isspace(parser->input[parser->offset])) ++parser->offset;
}

static int parse_name(struct parser *parser, char *target, size_t capacity) {
    size_t start = parser->offset;
    size_t amount;
    while (parser->offset < parser->length) {
        unsigned char value = parser->input[parser->offset];
        if (!(isalnum(value) || value == '_' || value == '-' || value == ':')) break;
        ++parser->offset;
    }
    amount = parser->offset - start;
    if (amount == 0U || amount >= capacity) {
        fail(parser, "invalid or oversized XML name");
        return -1;
    }
    memcpy(target, parser->input + start, amount);
    target[amount] = '\0';
    return 0;
}

static int append_utf8(char *target, size_t *length, size_t capacity, uint32_t value) {
    unsigned char encoded[4];
    size_t amount;
    if (value == 0U || value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU)) return -1;
    if (value < 0x80U) { encoded[0] = (unsigned char)value; amount = 1; }
    else if (value < 0x800U) {
        encoded[0] = (unsigned char)(0xc0U | (value >> 6));
        encoded[1] = (unsigned char)(0x80U | (value & 0x3fU)); amount = 2;
    } else if (value < 0x10000U) {
        encoded[0] = (unsigned char)(0xe0U | (value >> 12));
        encoded[1] = (unsigned char)(0x80U | ((value >> 6) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | (value & 0x3fU)); amount = 3;
    } else {
        encoded[0] = (unsigned char)(0xf0U | (value >> 18));
        encoded[1] = (unsigned char)(0x80U | ((value >> 12) & 0x3fU));
        encoded[2] = (unsigned char)(0x80U | ((value >> 6) & 0x3fU));
        encoded[3] = (unsigned char)(0x80U | (value & 0x3fU)); amount = 4;
    }
    if (*length + amount >= capacity) return -1;
    memcpy(target + *length, encoded, amount);
    *length += amount;
    target[*length] = '\0';
    return 0;
}

static int decode_text(const unsigned char *source, size_t amount,
                       char *target, size_t *length, size_t capacity) {
    size_t index = 0;
    while (index < amount) {
        if (source[index] != '&') {
            if (*length + 1U >= capacity) return -1;
            target[(*length)++] = (char)source[index++];
            target[*length] = '\0';
            continue;
        }
        {
            size_t end = index + 1U;
            uint32_t value = 0;
            while (end < amount && source[end] != ';' && end - index <= 12U) ++end;
            if (end >= amount || source[end] != ';') return -1;
            if (end - index == 4U && memcmp(source + index, "&lt;", 4) == 0) value = '<';
            else if (end - index == 4U && memcmp(source + index, "&gt;", 4) == 0) value = '>';
            else if (end - index == 5U && memcmp(source + index, "&amp;", 5) == 0) value = '&';
            else if (end - index == 6U && memcmp(source + index, "&quot;", 6) == 0) value = '"';
            else if (end - index == 6U && memcmp(source + index, "&apos;", 6) == 0) value = '\'';
            else if (source[index + 1U] == '#') {
                size_t digit = index + 2U;
                unsigned int base = 10U;
                if (digit < end && (source[digit] == 'x' || source[digit] == 'X')) { base = 16U; ++digit; }
                if (digit == end) return -1;
                for (; digit < end; ++digit) {
                    unsigned int part;
                    if (source[digit] >= '0' && source[digit] <= '9') part = source[digit] - '0';
                    else if (base == 16U && source[digit] >= 'a' && source[digit] <= 'f') part = source[digit] - 'a' + 10U;
                    else if (base == 16U && source[digit] >= 'A' && source[digit] <= 'F') part = source[digit] - 'A' + 10U;
                    else return -1;
                    if (value > (0x10ffffU - part) / base) return -1;
                    value = value * base + part;
                }
            } else return -1;
            if (append_utf8(target, length, capacity, value) != 0) return -1;
            index = end + 1U;
        }
    }
    return 0;
}

static int copy_attribute(struct parser *parser, char *target, size_t capacity) {
    unsigned char quote;
    size_t start;
    size_t decoded = 0;
    if (parser->offset >= parser->length ||
        (parser->input[parser->offset] != '"' && parser->input[parser->offset] != '\'')) return -1;
    quote = parser->input[parser->offset++];
    start = parser->offset;
    while (parser->offset < parser->length && parser->input[parser->offset] != quote) {
        if (parser->input[parser->offset] == '<') return -1;
        ++parser->offset;
    }
    if (parser->offset >= parser->length) return -1;
    target[0] = '\0';
    if (decode_text(parser->input + start, parser->offset - start,
                    target, &decoded, capacity) != 0) return -1;
    ++parser->offset;
    return 0;
}

static int assign_row_value(struct parser *parser, const char *parameter, const char *value) {
    size_t index = parser->depth;
    struct row_value *row = NULL;
    while (index > 0U) {
        --index;
        if (strcmp(parser->stack[index].name, "array") == 0) { row = &parser->stack[index].row; break; }
    }
    if (row == NULL) return 0;
#define ASSIGN_FIELD(field, seen, limit) \
    do { if (row->seen != 0U || strlen(value) > (limit)) return -1; \
         strcpy(row->field, value); row->seen = 1U; } while (0)
    if (strcmp(parameter, "name") == 0) ASSIGN_FIELD(name, seen_name, MAX_NAME_BYTES);
    else if (strcmp(parameter, "port") == 0) ASSIGN_FIELD(port, seen_port, 15U);
    else if (strcmp(parameter, "type") == 0) ASSIGN_FIELD(type, seen_type, 31U);
    else if (strcmp(parameter, "status") == 0) ASSIGN_FIELD(status, seen_status, 31U);
    else if (strcmp(parameter, "pduId_Index") == 0) ASSIGN_FIELD(pdu_name, seen_pdu_name, MAX_NAME_BYTES);
    else if (strcmp(parameter, "pdu_vendor") == 0) ASSIGN_FIELD(pdu_vendor, seen_pdu_vendor, MAX_NAME_BYTES);
    else if (strcmp(parameter, "pdu_model") == 0) ASSIGN_FIELD(pdu_model, seen_pdu_model, MAX_NAME_BYTES);
    else if (strcmp(parameter, "pdu_pos") == 0) ASSIGN_FIELD(pdu_pos, seen_pdu_pos, 15U);
    else if (strcmp(parameter, "pdu_status") == 0) ASSIGN_FIELD(pdu_status, seen_pdu_status, 31U);
    else if (strcmp(parameter, "pdu_current") == 0) ASSIGN_FIELD(pdu_current, seen_pdu_current, 31U);
    else if (strcmp(parameter, "pdu_power") == 0) ASSIGN_FIELD(pdu_power, seen_pdu_power, 31U);
    else if (strcmp(parameter, "pdu_alarm") == 0) ASSIGN_FIELD(pdu_alarm, seen_pdu_alarm, 63U);
    else if (strcmp(parameter, "thresholds") == 0) { /* intentionally not exposed */ }
    else if (strcmp(parameter, "action") == 0) {
        if (row->seen_action != 0U || value[0] != '\0') return -1;
        row->seen_action = 1U;
    } else row->unexpected = 1U;
#undef ASSIGN_FIELD
    return 0;
}

static int finalize_array(struct parser *parser, struct frame *frame) {
    struct row_value *row = &frame->row;
    size_t index;
    int inside_topology = 0, inside_pdu_table = 0;
    for (index = 0; index + 1U < parser->depth; ++index) {
        if (strcmp(parser->stack[index].name, "section") != 0 ||
            strcmp(parser->stack[index].structure, "table") != 0) continue;
        if (strcmp(parser->stack[index].id, "topologyTable") == 0) inside_topology = 1;
        if (strcmp(parser->stack[index].id, "pdu_devices_table") == 0) inside_pdu_table = 1;
    }
    if (inside_pdu_table) {
        char *end;
        unsigned long position, outlets_on, outlet_count;
        struct pdu *pdu;
        if (frame->id[0] == '\0' || row->unexpected != 0U ||
            row->seen_pdu_name != 1U || row->seen_pdu_vendor != 1U ||
            row->seen_pdu_model != 1U || row->seen_pdu_pos != 1U ||
            row->seen_pdu_status != 1U || row->seen_pdu_current != 1U ||
            row->seen_pdu_power != 1U || row->seen_pdu_alarm != 1U ||
            parser->pdu_count >= MAX_PDUS) return -1;
        errno = 0; position = strtoul(row->pdu_pos, &end, 10);
        if (errno != 0 || end == row->pdu_pos || *end != '\0' || position < 1UL || position > 65535UL) return -1;
        errno = 0; outlets_on = strtoul(row->pdu_status, &end, 10);
        if (errno != 0 || end == row->pdu_status || *end != '/' || outlets_on > 65535UL) return -1;
        {
            char *total_start = end + 1;
            errno = 0; outlet_count = strtoul(total_start, &end, 10);
            if (errno != 0 || end == total_start || *end != '\0' || outlet_count < 1UL ||
                outlet_count > 65535UL || outlets_on > outlet_count) return -1;
        }
        for (index = 0; index < parser->pdu_count; ++index)
            if (strcmp(parser->pdus[index].identity, frame->id) == 0) return -1;
        pdu = &parser->pdus[parser->pdu_count];
        strcpy(pdu->identity, frame->id); strcpy(pdu->name, row->pdu_name);
        strcpy(pdu->vendor, row->pdu_vendor); strcpy(pdu->model, row->pdu_model);
        strcpy(pdu->current, row->pdu_current); strcpy(pdu->power, row->pdu_power);
        strcpy(pdu->alarm, row->pdu_alarm);
        pdu->position = (unsigned int)position; pdu->outlets_on = (unsigned int)outlets_on;
        pdu->outlet_count = (unsigned int)outlet_count;
        if (pm3000_derive_id("pdu", pdu->identity, pdu->id) != 0) return -1;
        for (index = 0; index < parser->pdu_count; ++index)
            if (strcmp(parser->pdus[index].id, pdu->id) == 0) return -1;
        ++parser->pdu_count;
        return 0;
    }
    if (row->seen_type == 0U || strcmp(row->type, "outlet") != 0) return 0;
    if (!inside_topology) return -1;
    if (row->seen_name != 1U || row->seen_port != 1U || row->seen_status != 1U ||
        row->seen_action != 1U || row->unexpected != 0U || frame->id[0] == '\0') return -1;
    if (parser->outlet_count >= MAX_OUTLETS) return -1;
    for (index = parser->depth - 1U; index > 0U; --index) {
        struct frame *parent = &parser->stack[index - 1U];
        if (strcmp(parent->name, "array") == 0) {
            if (parent->id[0] == '\0') return -1;
            strncpy(row->pdu_identity, parent->id, sizeof(row->pdu_identity) - 1U);
            break;
        }
    }
    if (row->pdu_identity[0] == '\0') return -1;
    {
        char *end = NULL;
        unsigned long position;
        struct outlet *outlet = &parser->outlets[parser->outlet_count];
        char canonical_position[16];
        errno = 0;
        position = strtoul(row->port, &end, 10);
        if (errno != 0 || end == row->port || *end != '\0' || position < 1UL || position > 256UL ||
            snprintf(canonical_position, sizeof(canonical_position), "%lu", position) < 0 ||
            strcmp(canonical_position, row->port) != 0) return -1;
        for (index = 0; index < parser->outlet_count; ++index) {
            if (strcmp(parser->outlets[index].identity, frame->id) == 0 ||
                (strcmp(parser->outlets[index].pdu_identity, row->pdu_identity) == 0 &&
                 parser->outlets[index].position == (unsigned int)position)) return -1;
        }
        strcpy(outlet->identity, frame->id);
        strcpy(outlet->pdu_identity, row->pdu_identity);
        strcpy(outlet->name, row->name);
        outlet->position = (unsigned int)position;
        outlet->state = strcmp(row->status, "ON") == 0 ? "on" : strcmp(row->status, "OFF") == 0 ? "off" : "unknown";
        if (pm3000_derive_id("outlet", outlet->identity, outlet->id) != 0 ||
            pm3000_derive_id("pdu", outlet->pdu_identity, outlet->pdu_id) != 0) return -1;
        for (index = 0; index < parser->outlet_count; ++index) {
            if (strcmp(parser->outlets[index].id, outlet->id) == 0 &&
                strcmp(parser->outlets[index].identity, outlet->identity) != 0) return -1;
            if (strcmp(parser->outlets[index].pdu_id, outlet->pdu_id) == 0 &&
                strcmp(parser->outlets[index].pdu_identity, outlet->pdu_identity) != 0) return -1;
        }
        ++parser->outlet_count;
    }
    return 0;
}

static int close_frame(struct parser *parser, const char *name) {
    struct frame *frame;
    if (parser->depth == 0U) return -1;
    frame = &parser->stack[parser->depth - 1U];
    if (strcmp(frame->name, name) != 0) return -1;
    if (strcmp(name, "value") == 0) {
        size_t index = parser->depth - 1U;
        const char *parameter = NULL;
        while (index > 0U) {
            --index;
            if (strcmp(parser->stack[index].name, "parameter") == 0) {
                parameter = parser->stack[index].parameter_id;
                break;
            }
        }
        if (parameter != NULL && assign_row_value(parser, parameter, frame->text) != 0) return -1;
    } else if (strcmp(name, "action") == 0 && parser->depth == 2U) {
        if (++parser->action_count != 1U) return -1;
        strcpy(parser->action, frame->text);
    } else if (strcmp(name, "path") == 0) {
        if (++parser->path_count != 1U) return -1;
        strcpy(parser->path, frame->text);
    } else if (strcmp(name, "array") == 0) {
        if (finalize_array(parser, frame) != 0) return -1;
    }
    --parser->depth;
    return 0;
}

static int start_element(struct parser *parser, int *self_closing) {
    struct frame *frame;
    char attribute_names[MAX_ATTRIBUTES][32];
    size_t attribute_count = 0;
    if (parser->depth >= MAX_DEPTH) return -1;
    frame = &parser->stack[parser->depth];
    memset(frame, 0, sizeof(*frame));
    if (parse_name(parser, frame->name, sizeof(frame->name)) != 0 || !known_element(frame->name)) return -1;
    while (1) {
        char name[32];
        char value[MAX_IDENTITY_BYTES + 1U];
        size_t index;
        skip_space(parser);
        if (parser->offset >= parser->length) return -1;
        if (parser->input[parser->offset] == '>') { ++parser->offset; *self_closing = 0; break; }
        if (parser->input[parser->offset] == '/' && parser->offset + 1U < parser->length && parser->input[parser->offset + 1U] == '>') {
            parser->offset += 2U; *self_closing = 1; break;
        }
        if (attribute_count >= MAX_ATTRIBUTES || parse_name(parser, name, sizeof(name)) != 0) return -1;
        for (index = 0; index < attribute_count; ++index) if (strcmp(name, attribute_names[index]) == 0) return -1;
        strcpy(attribute_names[attribute_count++], name);
        skip_space(parser);
        if (parser->offset >= parser->length || parser->input[parser->offset++] != '=') return -1;
        skip_space(parser);
        if (copy_attribute(parser, value, sizeof(value)) != 0) return -1;
        if (strcmp(name, "id") == 0) {
            if (strlen(value) > MAX_IDENTITY_BYTES) return -1;
            strcpy(frame->id, value);
            if (strcmp(frame->name, "parameter") == 0) strcpy(frame->parameter_id, value);
        } else if (strcmp(name, "structure") == 0) {
            if (strlen(value) >= sizeof(frame->structure)) return -1;
            strcpy(frame->structure, value);
        }
    }
    if (parser->depth == 0U) {
        if (strcmp(frame->name, "avtrans") != 0 || ++parser->root_count != 1U) return -1;
    }
    if (strcmp(frame->name, "section") == 0 && strcmp(frame->id, "topologyTable") == 0) {
        if (strcmp(frame->structure, "table") != 0 || ++parser->topology_count != 1U) return -1;
    }
    if (strcmp(frame->name, "section") == 0 && strcmp(frame->id, "pdu_devices_table") == 0) {
        if (strcmp(frame->structure, "table") != 0 || ++parser->pdu_table_count != 1U) return -1;
    }
    if (strcmp(frame->name, "control") == 0) {
        size_t parent;
        int inside_pdu = 0;
        for (parent = 0U; parent < parser->depth; ++parent)
            if (strcmp(parser->stack[parent].name, "section") == 0 &&
                strcmp(parser->stack[parent].id, "pdu_devices_table") == 0) inside_pdu = 1;
        if (inside_pdu) {
            if (strcmp(frame->id, "on") == 0) ++parser->pdu_on;
            else if (strcmp(frame->id, "off") == 0) ++parser->pdu_off;
            else if (strcmp(frame->id, "cycle") == 0) ++parser->pdu_cycle;
        }
    }
    ++parser->depth;
    if (*self_closing != 0 && close_frame(parser, frame->name) != 0) return -1;
    return 0;
}

static int parse_document(struct parser *parser) {
    while (parser->offset < parser->length) {
        if (parser->input[parser->offset] != '<') {
            size_t start = parser->offset;
            struct frame *frame;
            while (parser->offset < parser->length && parser->input[parser->offset] != '<') ++parser->offset;
            if (parser->depth == 0U) {
                size_t index;
                for (index = start; index < parser->offset; ++index) if (!isspace(parser->input[index])) return -1;
                continue;
            }
            frame = &parser->stack[parser->depth - 1U];
            if (strcmp(frame->name, "value") == 0 ||
                (strcmp(frame->name, "action") == 0 && parser->depth == 2U) || strcmp(frame->name, "path") == 0) {
                if (decode_text(parser->input + start, parser->offset - start,
                                frame->text, &frame->text_length, sizeof(frame->text)) != 0) return -1;
            }
            continue;
        }
        ++parser->offset;
        if (parser->offset >= parser->length) return -1;
        if (parser->input[parser->offset] == '?') {
            static const char vendor_declaration[] = "xml version=\"1.0\"";
            static const char vendor_stylesheet[] =
                "xml-stylesheet type=\"text/xsl\" href=\"transformation.xsl\"";
            const unsigned char *end;
            size_t content_start = parser->offset + 1U;
            size_t content_length;
            end = (const unsigned char *)strstr((const char *)parser->input + parser->offset, "?>");
            if (end == NULL) return -1;
            content_length = (size_t)(end - parser->input) - content_start;
            if (parser->offset == 1U) {
                if (content_length != sizeof(vendor_declaration) - 1U ||
                    memcmp(parser->input + content_start, vendor_declaration,
                           sizeof(vendor_declaration) - 1U) != 0) return -1;
                ++parser->xml_declarations;
            } else {
                if (parser->depth != 0U || parser->root_count != 0U ||
                    parser->xml_declarations != 1U ||
                    parser->vendor_stylesheets != 0U ||
                    content_length != sizeof(vendor_stylesheet) - 1U ||
                    memcmp(parser->input + content_start, vendor_stylesheet,
                           sizeof(vendor_stylesheet) - 1U) != 0) return -1;
                ++parser->vendor_stylesheets;
            }
            parser->offset = (size_t)(end - parser->input) + 2U;
        } else if (parser->input[parser->offset] == '!') {
            return -1;
        } else if (parser->input[parser->offset] == '/') {
            char name[32];
            ++parser->offset;
            if (parse_name(parser, name, sizeof(name)) != 0) return -1;
            skip_space(parser);
            if (parser->offset >= parser->length || parser->input[parser->offset++] != '>' || close_frame(parser, name) != 0) return -1;
        } else {
            int self_closing;
            if (start_element(parser, &self_closing) != 0) return -1;
        }
    }
    if (parser->depth != 0U || parser->root_count != 1U || parser->action_count != 1U ||
        strcmp(parser->action, "content") != 0 || parser->path_count != 1U) return -1;
    if (parser->mode == 0) {
        if (strcmp(parser->path, "units.topology") != 0 || parser->topology_count != 1U ||
            parser->pdu_table_count != 0U || parser->outlet_count == 0U) return -1;
    } else {
        if (strcmp(parser->path, "units.powermanagement.pdu_management") != 0 ||
            parser->pdu_table_count != 1U || parser->topology_count != 0U ||
            parser->pdu_count == 0U) return -1;
    }
    return 0;
}

static void json_string(FILE *output, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    fputc('"', output);
    while (*cursor != 0U) {
        if (*cursor == '"' || *cursor == '\\') { fputc('\\', output); fputc(*cursor, output); }
        else if (*cursor < 0x20U) fprintf(output, "\\u%04x", (unsigned int)*cursor);
        else fputc(*cursor, output);
        ++cursor;
    }
    fputc('"', output);
}

static void emit_outlet(FILE *output, const struct outlet *outlet) {
    fputs("{\"id\":", output); json_string(output, outlet->id);
    fputs(",\"pduId\":", output); json_string(output, outlet->pdu_id);
    fprintf(output, ",\"position\":%u,\"name\":", outlet->position); json_string(output, outlet->name);
    fputs(",\"state\":", output); json_string(output, outlet->state);
    fputs(",\"availableActions\":[]}", output);
}

static int outlet_allowed(const char *id, int unrestricted,
                          const char *outlets, unsigned int outlet_count) {
    unsigned int index;
    if (unrestricted) return 1;
    for (index = 0; index < outlet_count; ++index) if (strcmp(id, outlets + index * 23U) == 0) return 1;
    return 0;
}

static int emit_inventory(struct parser *parser, FILE *output, int unrestricted,
                          const char *outlets, unsigned int outlet_count) {
    char *identities[MAX_OUTLETS];
    char revision[PM3000_ID_LENGTH + 1U];
    size_t index;
    unsigned int emitted = 0;
    for (index = 0; index < parser->outlet_count; ++index) identities[index] = parser->outlets[index].identity;
    if (pm3000_inventory_revision(identities, parser->outlet_count, revision) != 0) return -1;
    fputs("{\"apiVersion\":\"v1\",\"inventoryRevision\":", output);
    json_string(output, revision);
    fputs(",\"outlets\":[", output);
    for (index = 0; index < parser->outlet_count; ++index) {
        struct outlet *outlet = &parser->outlets[index];
        if (!outlet_allowed(outlet->id, unrestricted, outlets, outlet_count)) continue;
        if (emitted++ != 0U) fputc(',', output);
        emit_outlet(output, outlet);
    }
    fputs("]}\n", output);
    return ferror(output) ? -1 : 0;
}

static int emit_pdus(struct parser *parser, FILE *output) {
    char *identities[MAX_PDUS];
    char revision[PM3000_ID_LENGTH + 1U];
    size_t index;
    int can_control = parser->pdu_on == 1U && parser->pdu_off == 1U && parser->pdu_cycle == 1U;
    for (index = 0; index < parser->pdu_count; ++index) identities[index] = parser->pdus[index].identity;
    if (pm3000_inventory_revision(identities, parser->pdu_count, revision) != 0) return -1;
    fputs("{\"apiVersion\":\"v1\",\"inventoryRevision\":", output); json_string(output, revision);
    fputs(",\"pdus\":[", output);
    for (index = 0; index < parser->pdu_count; ++index) {
        const struct pdu *pdu = &parser->pdus[index];
        if (index != 0U) fputc(',', output);
        fputs("{\"id\":", output); json_string(output, pdu->id);
        fputs(",\"name\":", output); json_string(output, pdu->name);
        fputs(",\"vendor\":", output); json_string(output, pdu->vendor);
        fputs(",\"model\":", output); json_string(output, pdu->model);
        fprintf(output, ",\"position\":%u,\"outletsOn\":%u,\"outletCount\":%u,\"currentAmps\":",
                pdu->position, pdu->outlets_on, pdu->outlet_count);
        json_string(output, pdu->current); fputs(",\"powerWatts\":", output); json_string(output, pdu->power);
        fputs(",\"alarm\":", output); json_string(output, pdu->alarm);
        fputs(can_control ? ",\"availableActions\":[\"on\",\"off\",\"cycle\"]}" :
                            ",\"availableActions\":[]}", output);
    }
    fputs("]}\n", output);
    return ferror(output) ? -1 : 0;
}

int pm3000_project_bytes_filtered(const unsigned char *xml, unsigned long length, FILE *output,
                                  int unrestricted, const char *outlets,
                                  unsigned int outlet_count, char *error,
                                  unsigned int error_size) {
    struct parser parser;
    memset(&parser, 0, sizeof(parser));
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length) ||
        (!unrestricted && outlets == NULL && outlet_count != 0U)) {
        (void)snprintf(error, error_size, "backend XML has invalid size or UTF-8");
        return -1;
    }
    parser.input = xml;
    parser.length = (size_t)length;
    if (parse_document(&parser) != 0 ||
        (output != NULL && emit_inventory(&parser, output, unrestricted, outlets, outlet_count) != 0)) {
        (void)snprintf(error, error_size, "%s", parser.error[0] != '\0' ? parser.error : "backend XML violates the topology contract");
        return -1;
    }
    return 0;
}

int pm3000_project_bytes(const unsigned char *xml, unsigned long length, FILE *output,
                          char *error, unsigned int error_size) {
    return pm3000_project_bytes_filtered(xml, length, output, 1, NULL, 0U, error, error_size);
}

int pm3000_project_pdus_bytes(const unsigned char *xml, unsigned long length, FILE *output,
                              char *error, unsigned int error_size) {
    struct parser parser;
    memset(&parser, 0, sizeof(parser)); parser.mode = 1;
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length)) return -1;
    parser.input = xml; parser.length = (size_t)length;
    if (parse_document(&parser) != 0 ||
        (output != NULL && emit_pdus(&parser, output) != 0)) {
        (void)snprintf(error, error_size, "backend XML violates the PDU contract"); return -1;
    }
    return 0;
}

int pm3000_confirm_outlet_action(const unsigned char *xml, unsigned long length,
                                 const char *identity, const char *action) {
    struct parser parser;
    size_t index;
    const char *expected;
    memset(&parser, 0, sizeof(parser));
    if (strcmp(action, "on") == 0) expected = "on";
    else if (strcmp(action, "off") == 0) expected = "off";
    else return -1;
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length)) return -1;
    parser.input = xml; parser.length = (size_t)length;
    if (parse_document(&parser) != 0) return -1;
    for (index = 0U; index < parser.outlet_count; ++index)
        if (strcmp(parser.outlets[index].identity, identity) == 0)
            return strcmp(parser.outlets[index].state, expected) == 0 ? 0 : -1;
    return -1;
}

int pm3000_confirm_pdu_action(const unsigned char *xml, unsigned long length,
                              const char *identity, const char *action) {
    struct parser parser;
    size_t index;
    memset(&parser, 0, sizeof(parser)); parser.mode = 1;
    if (strcmp(action, "on") != 0 && strcmp(action, "off") != 0) return -1;
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length)) return -1;
    parser.input = xml; parser.length = (size_t)length;
    if (parse_document(&parser) != 0) return -1;
    for (index = 0U; index < parser.pdu_count; ++index) {
        const struct pdu *pdu = &parser.pdus[index];
        if (strcmp(pdu->identity, identity) != 0) continue;
        if (strcmp(action, "on") == 0) return pdu->outlets_on == pdu->outlet_count ? 0 : -1;
        return pdu->outlets_on == 0U ? 0 : -1;
    }
    return -1;
}

int pm3000_resolve_pdu_identity(const unsigned char *xml, unsigned long length,
                                const char *pdu_id, const char *revision,
                                char *identity, size_t identity_size,
                                char *error, unsigned int error_size) {
    struct parser parser;
    char *identities[MAX_PDUS];
    char current_revision[PM3000_ID_LENGTH + 1U];
    size_t index;
    memset(&parser, 0, sizeof(parser)); parser.mode = 1;
    if (strlen(pdu_id) != PM3000_ID_LENGTH || strlen(revision) != PM3000_ID_LENGTH ||
        length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length)) return -1;
    parser.input = xml; parser.length = (size_t)length;
    if (parse_document(&parser) != 0) return -1;
    for (index = 0; index < parser.pdu_count; ++index) identities[index] = parser.pdus[index].identity;
    if (pm3000_inventory_revision(identities, parser.pdu_count, current_revision) != 0 ||
        strcmp(current_revision, revision) != 0) {
        (void)snprintf(error, error_size, "inventory revision is stale"); return 1;
    }
    for (index = 0; index < parser.pdu_count; ++index) {
        if (strcmp(parser.pdus[index].id, pdu_id) == 0) {
            if (parser.pdu_on != 1U || parser.pdu_off != 1U || parser.pdu_cycle != 1U) {
                (void)snprintf(error, error_size, "PDU control denied"); return 4;
            }
            if (strlen(parser.pdus[index].identity) + 1U > identity_size) return -1;
            strcpy(identity, parser.pdus[index].identity); return 0;
        }
    }
    (void)snprintf(error, error_size, "PDU not found"); return 2;
}

int pm3000_project_detail_bytes(const unsigned char *xml, unsigned long length,
                                const char *outlet_id, FILE *output,
                                char *error, unsigned int error_size) {
    struct parser parser;
    size_t index;
    memset(&parser, 0, sizeof(parser));
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length) ||
        strlen(outlet_id) != PM3000_ID_LENGTH) return -1;
    parser.input = xml; parser.length = (size_t)length;
    if (parse_document(&parser) != 0) return -1;
    for (index = 0; index < parser.outlet_count; ++index) {
        if (strcmp(parser.outlets[index].id, outlet_id) == 0) {
            if (output != NULL) { emit_outlet(output, &parser.outlets[index]); fputc('\n', output); }
            return output != NULL && ferror(output) ? -1 : 0;
        }
    }
    (void)snprintf(error, error_size, "outlet not found");
    return 1;
}

int pm3000_resolve_outlet_identity(const unsigned char *xml, unsigned long length,
                                   const char *outlet_id, const char *revision,
                                   char *identity, size_t identity_size,
                                   char *error, unsigned int error_size) {
    struct parser parser;
    char *identities[MAX_OUTLETS];
    char actual_revision[PM3000_ID_LENGTH + 1U];
    size_t index;
    memset(&parser, 0, sizeof(parser));
    if (length == 0UL || length > MAX_XML_BYTES || !valid_utf8(xml, (size_t)length) ||
        strlen(outlet_id) != PM3000_ID_LENGTH || strlen(revision) != PM3000_ID_LENGTH) return -1;
    parser.input = xml;
    parser.length = (size_t)length;
    if (parse_document(&parser) != 0) return -1;
    for (index = 0; index < parser.outlet_count; ++index) identities[index] = parser.outlets[index].identity;
    if (pm3000_inventory_revision(identities, parser.outlet_count, actual_revision) != 0) return -1;
    if (strcmp(actual_revision, revision) != 0) {
        (void)snprintf(error, error_size, "inventory revision changed");
        return 2;
    }
    for (index = 0; index < parser.outlet_count; ++index) {
        if (strcmp(parser.outlets[index].id, outlet_id) == 0) {
            if (strlen(parser.outlets[index].identity) + 1U > identity_size) return -1;
            strcpy(identity, parser.outlets[index].identity);
            return 0;
        }
    }
    (void)snprintf(error, error_size, "outlet not found");
    return 1;
}

int pm3000_project_detail_file(const char *path, const char *outlet_id, FILE *output,
                               char *error, unsigned int error_size) {
    int descriptor;
    struct stat metadata;
    unsigned char *buffer;
    size_t used = 0;
    int result;
    descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 || (unsigned long)metadata.st_size > MAX_XML_BYTES) {
        if (descriptor >= 0) close(descriptor);
        return -1;
    }
    buffer = (unsigned char *)malloc((size_t)metadata.st_size);
    if (buffer == NULL) { close(descriptor); return -1; }
    while (used < (size_t)metadata.st_size) {
        ssize_t amount = read(descriptor, buffer + used, (size_t)metadata.st_size - used);
        if (amount <= 0) { free(buffer); close(descriptor); return -1; }
        used += (size_t)amount;
    }
    close(descriptor);
    result = pm3000_project_detail_bytes(buffer, (unsigned long)used, outlet_id, output, error, error_size);
    free(buffer);
    return result;
}

int pm3000_project_file(const char *path, FILE *output, char *error, unsigned int error_size) {
    int descriptor;
    struct stat metadata;
    unsigned char *buffer;
    size_t used = 0;
    int result;
    descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_size <= 0 || (unsigned long)metadata.st_size > MAX_XML_BYTES) {
        if (descriptor >= 0) close(descriptor);
        (void)snprintf(error, error_size, "backend fixture must be a regular file of at most 1 MiB");
        return -1;
    }
    buffer = (unsigned char *)malloc((size_t)metadata.st_size + 1U);
    if (buffer == NULL) { close(descriptor); return -1; }
    while (used < (size_t)metadata.st_size) {
        ssize_t amount = read(descriptor, buffer + used, (size_t)metadata.st_size - used);
        if (amount <= 0) { free(buffer); close(descriptor); return -1; }
        used += (size_t)amount;
    }
    close(descriptor);
    buffer[used] = '\0';
    result = pm3000_project_bytes(buffer, (unsigned long)used, output, error, error_size);
    free(buffer);
    return result;
}
