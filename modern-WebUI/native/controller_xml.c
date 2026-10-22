#include "controller_xml.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define XML_MAX_BYTES (1024U * 1024U)
#define XML_MAX_DEPTH 32U
#define XML_MAX_NAME 63U
#define XML_MAX_TEXT 512U
#define XML_MAX_ATTRS 32U
#define XML_MAX_PATHS 64U
#define XML_MAX_PARAMETERS 128U
#define XML_MAX_ROW_PARAMS 256U

struct frame {
    char name[XML_MAX_NAME + 1U];
    char id[XML_MAX_TEXT + 1U];
    char structure[XML_MAX_NAME + 1U];
    char path[XML_MAX_TEXT + 1U];
    char access_path[XML_MAX_TEXT + 1U];
    char access_rights[XML_MAX_NAME + 1U];
    char text[XML_MAX_TEXT + 1U];
    char attribute_value[33];
    size_t text_length;
    unsigned int fixed_child_stage;
};

struct parameter_value {
    char form[XML_MAX_TEXT + 1U];
    char parameter[XML_MAX_TEXT + 1U];
    char structure[XML_MAX_NAME + 1U];
    char container_name[XML_MAX_NAME + 1U];
    char container_id[XML_MAX_TEXT + 1U];
    char container_structure[XML_MAX_NAME + 1U];
    char container_attribute_value[33];
    unsigned int direct_form_child;
    char value[XML_MAX_TEXT + 1U];
};

struct parameter_declaration {
    char form[XML_MAX_TEXT + 1U];
    char parameter[XML_MAX_TEXT + 1U];
    char structure[XML_MAX_NAME + 1U];
    char container_name[XML_MAX_NAME + 1U];
    char container_id[XML_MAX_TEXT + 1U];
    char container_structure[XML_MAX_NAME + 1U];
    char container_attribute_value[33];
    unsigned int direct_form_child;
    char attribute_value[33];
};

struct option_value {
    char form[XML_MAX_NAME + 1U];
    char parameter[XML_MAX_NAME + 1U];
    char value[33];
};

struct xml_row_param {
    char table_id[XML_MAX_NAME + 1U];
    char parameter[XML_MAX_NAME + 1U];
    char structure[XML_MAX_NAME + 1U];
    char value[XML_MAX_TEXT + 1U];
    unsigned int row;
    unsigned int direct_row_child;
};

struct document {
    const unsigned char *input;
    size_t length;
    size_t offset;
    struct frame stack[XML_MAX_DEPTH];
    size_t depth;
    unsigned int roots;
    unsigned int actions;
    unsigned int paths;
    unsigned int sids;
    unsigned int errors;
    unsigned int payloads;
    unsigned int vendor_stylesheets;
    char action[XML_MAX_TEXT + 1U];
    char path[XML_MAX_TEXT + 1U];
    char sid[129];
    char payload_structure[XML_MAX_NAME + 1U];
    char navigation_paths[XML_MAX_PATHS][XML_MAX_TEXT + 1U];
    unsigned int navigation_count;
    unsigned int power_on;
    unsigned int power_off;
    unsigned int power_cycle;
    unsigned int password_changed_section;
    unsigned int password_info_form;
    unsigned int password_title;
    unsigned int password_message;
    struct parameter_value parameter_values[XML_MAX_PARAMETERS];
    unsigned int parameter_value_count;
    struct parameter_declaration parameter_declarations[XML_MAX_PARAMETERS];
    unsigned int parameter_declaration_count;
    unsigned int payload_parameter_count;
    unsigned int payload_section_count;
    unsigned int payload_value_count;
    unsigned int payload_option_count;
    unsigned int direct_payload_forms;
    unsigned int direct_payload_controls;
    unsigned int unexpected_payload_elements;
    unsigned int unexpected_payload_text;
    unsigned int unexpected_envelope_elements;
    unsigned int unexpected_envelope_text;
    unsigned int unexpected_fixed_attributes;
    unsigned int unexpected_fixed_sequence;
    unsigned int fixed_envelope_stage;
    unsigned int fixed_payload_stage;
    struct option_value *option_values;
    unsigned int option_value_count;
    char form_ids[32][XML_MAX_TEXT + 1U];
    unsigned int form_count;
    unsigned int control_count;
    unsigned int save_controls;
    unsigned int help_language_capability;
    unsigned int data_buffering_capability;
    unsigned int appliance_logging_capability;
    unsigned int time_zone_capability;
    char table_id[XML_MAX_NAME + 1U];
    char current_table_id[XML_MAX_NAME + 1U];
    unsigned int table_count;
    int current_row_index;
    unsigned int table_row_count;
    unsigned int unexpected_table_rows;
    unsigned int row_param_count;
    unsigned int row_overflow;
    struct xml_row_param row_params[XML_MAX_ROW_PARAMS];
};

static int valid_utf8(const unsigned char *input, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        unsigned char first = input[offset++];
        uint32_t value;
        size_t remaining;
        if (first < 0x80U) {
            if ((first < 0x20U && first != 0x09U && first != 0x0aU && first != 0x0dU))
                return 0;
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
        if ((value >= 0xd800U && value <= 0xdfffU) || value == 0xfffeU ||
            value == 0xffffU || value > 0x10ffffU ||
            value < (first <= 0xdfU ? 0x80U : first <= 0xefU ? 0x800U : 0x10000U)) return 0;
    }
    return 1;
}

static int declaration_space(unsigned char value) {
    return value == ' ' || value == '\t' || value == '\n' || value == '\r';
}

static int declaration_span(const unsigned char *input, size_t start,
                            size_t length, const char *expected) {
    return strlen(expected) == length && memcmp(input + start, expected, length) == 0;
}

static int valid_xml_declaration(const unsigned char *input, size_t length) {
    size_t offset = 0U;
    unsigned int attribute = 0U;
    int saw_standalone = 0;
    if (length < 4U || memcmp(input, "xml", 3U) != 0 ||
        !declaration_space(input[3U])) return 0;
    offset = 3U;
    while (offset < length) {
        size_t separator_start = offset;
        size_t name_start, name_length, value_start, value_length;
        unsigned char quote;
        while (offset < length && declaration_space(input[offset])) ++offset;
        if (offset == length) break;
        if (offset == separator_start) return 0;
        name_start = offset;
        while (offset < length &&
               ((input[offset] >= 'A' && input[offset] <= 'Z') ||
                (input[offset] >= 'a' && input[offset] <= 'z'))) ++offset;
        name_length = offset - name_start;
        if (name_length == 0U) return 0;
        while (offset < length && declaration_space(input[offset])) ++offset;
        if (offset >= length || input[offset++] != '=') return 0;
        while (offset < length && declaration_space(input[offset])) ++offset;
        if (offset >= length || (input[offset] != '\'' && input[offset] != '"')) return 0;
        quote = input[offset++];
        value_start = offset;
        while (offset < length && input[offset] != quote) ++offset;
        if (offset >= length) return 0;
        value_length = offset - value_start;
        ++offset;
        if (attribute == 0U) {
            if (!declaration_span(input, name_start, name_length, "version") ||
                !declaration_span(input, value_start, value_length, "1.0")) return 0;
        } else if (attribute == 1U &&
                   declaration_span(input, name_start, name_length, "encoding")) {
            if (value_length != 5U ||
                !((input[value_start] == 'U' || input[value_start] == 'u') &&
                  (input[value_start + 1U] == 'T' || input[value_start + 1U] == 't') &&
                  (input[value_start + 2U] == 'F' || input[value_start + 2U] == 'f') &&
                  input[value_start + 3U] == '-' && input[value_start + 4U] == '8')) return 0;
        } else if ((attribute == 1U || attribute == 2U) &&
                   declaration_span(input, name_start, name_length, "standalone")) {
            if (saw_standalone ||
                !(declaration_span(input, value_start, value_length, "yes") ||
                  declaration_span(input, value_start, value_length, "no"))) return 0;
            saw_standalone = 1;
        } else return 0;
        ++attribute;
        if (saw_standalone) {
            while (offset < length && declaration_space(input[offset])) ++offset;
            return offset == length;
        }
    }
    return attribute == 1U || attribute == 2U;
}

static int valid_vendor_stylesheet(const unsigned char *input, size_t length) {
    static const char expected[] =
        "xml-stylesheet type=\"text/xsl\" href=\"transformation.xsl\"";
    return length == sizeof(expected) - 1U &&
           memcmp(input, expected, sizeof(expected) - 1U) == 0;
}

static void skip_space(struct document *document) {
    while (document->offset < document->length &&
           isspace((unsigned char)document->input[document->offset]))
        ++document->offset;
}

static int parse_name(struct document *document, char *output, size_t capacity) {
    size_t start = document->offset;
    size_t amount;
    unsigned char value;
    if (document->offset >= document->length) return -1;
    value = document->input[document->offset];
    if (!(isalpha(value) || value == '_')) return -1;
    ++document->offset;
    while (document->offset < document->length) {
        value = document->input[document->offset];
        if (!(isalnum(value) || value == '_' || value == '-' || value == '.')) break;
        ++document->offset;
    }
    amount = document->offset - start;
    if (amount >= capacity) return -1;
    memcpy(output, document->input + start, amount);
    output[amount] = '\0';
    return 0;
}

static int append_byte(char *output, size_t *length, size_t capacity,
                       unsigned char value) {
    if (value == 0U ||
        (value < 0x20U && value != 0x09U && value != 0x0aU && value != 0x0dU) ||
        *length + 1U >= capacity) return -1;
    output[(*length)++] = (char)value;
    output[*length] = '\0';
    return 0;
}

static int decode(const unsigned char *input, size_t amount,
                  char *output, size_t *length, size_t capacity) {
    size_t offset = 0U;
    while (offset < amount) {
        unsigned char value = input[offset++];
        if (value != '&') {
            if (append_byte(output, length, capacity, value) != 0) return -1;
        } else {
            size_t remaining = amount - (offset - 1U);
            if (remaining >= 4U && memcmp(input + offset - 1U, "&lt;", 4U) == 0) {
                value = '<'; offset += 3U;
            } else if (remaining >= 4U && memcmp(input + offset - 1U, "&gt;", 4U) == 0) {
                value = '>'; offset += 3U;
            } else if (remaining >= 5U && memcmp(input + offset - 1U, "&amp;", 5U) == 0) {
                value = '&'; offset += 4U;
            } else if (remaining >= 6U && memcmp(input + offset - 1U, "&quot;", 6U) == 0) {
                value = '"'; offset += 5U;
            } else if (remaining >= 6U && memcmp(input + offset - 1U, "&apos;", 6U) == 0) {
                value = '\''; offset += 5U;
            } else return -1;
            if (append_byte(output, length, capacity, value) != 0) return -1;
        }
    }
    return 0;
}

static int attribute_value(struct document *document, char *output,
                           size_t capacity) {
    unsigned char quote;
    size_t start, length = 0U;
    if (document->offset >= document->length ||
        (document->input[document->offset] != '"' &&
         document->input[document->offset] != '\'')) return -1;
    quote = document->input[document->offset++];
    start = document->offset;
    while (document->offset < document->length &&
           document->input[document->offset] != quote) {
        if (document->input[document->offset] == '<') return -1;
        ++document->offset;
    }
    if (document->offset >= document->length) return -1;
    output[0] = '\0';
    if (decode(document->input + start, document->offset - start,
               output, &length, capacity) != 0) return -1;
    ++document->offset;
    return 0;
}

static int ancestor_is(const struct document *document, size_t back,
                       const char *name) {
    return document->depth >= back &&
           strcmp(document->stack[document->depth - back].name, name) == 0;
}

static int has_ancestor(const struct document *document, const char *name) {
    size_t index;
    for (index = 0U; index < document->depth; ++index)
        if (strcmp(document->stack[index].name, name) == 0) return 1;
    return 0;
}

static const char *ancestor_form_id(const struct document *document) {
    size_t index = document->depth;
    while (index > 0U) {
        const struct frame *frame = &document->stack[--index];
        if (strcmp(frame->name, "section") == 0 &&
            strcmp(frame->structure, "form") == 0) return frame->id;
    }
    return NULL;
}

static int remember_navigation_path(struct document *document,
                                    const char *path) {
    unsigned int index;
    if (path[0] == '\0' || document->navigation_count >= XML_MAX_PATHS) return -1;
    for (index = 0U; index < document->navigation_count; ++index)
        if (strcmp(document->navigation_paths[index], path) == 0) return -1;
    strcpy(document->navigation_paths[document->navigation_count++], path);
    return 0;
}

static int close_element(struct document *document, const char *name) {
    struct frame *frame;
    if (document->depth == 0U) return -1;
    frame = &document->stack[document->depth - 1U];
    if (strcmp(frame->name, name) != 0) return -1;
    if (strcmp(name, "action") == 0 && document->depth != 2U) return -1;
    if (strcmp(name, "sid") == 0 && document->depth != 2U) return -1;
    if (strcmp(name, "path") == 0 &&
        !(document->depth == 3U && ancestor_is(document, 2U, "paths") &&
          ancestor_is(document, 3U, "avtrans"))) return -1;
    if (strcmp(name, "value") == 0 && document->depth >= 2U &&
        strcmp(document->stack[document->depth - 2U].name, "parameter") == 0 &&
        has_ancestor(document, "payload")) {
        const char *form = ancestor_form_id(document);
        struct frame *parameter = &document->stack[document->depth - 2U];
        if (form != NULL) {
            struct parameter_value *record;
            if (form[0] == '\0' || parameter->id[0] == '\0' ||
                document->parameter_value_count >= XML_MAX_PARAMETERS) return -1;
            record = &document->parameter_values[document->parameter_value_count++];
            strcpy(record->form, form);
            strcpy(record->parameter, parameter->id);
            strcpy(record->structure, parameter->structure);
            if (document->depth >= 3U) {
                const struct frame *container = &document->stack[document->depth - 3U];
                strcpy(record->container_name, container->name);
                strcpy(record->container_id, container->id);
                strcpy(record->container_structure, container->structure);
                strcpy(record->container_attribute_value, container->attribute_value);
                record->direct_form_child =
                    strcmp(container->name, "section") == 0 &&
                    strcmp(container->id, form) == 0 &&
                    strcmp(container->structure, "form") == 0;
            }
            strcpy(record->value, frame->text);
        } else if (document->current_row_index >= 0 &&
                   parameter->id[0] != '\0' &&
                   strlen(parameter->id) <= XML_MAX_NAME) {
            if (document->row_param_count >= XML_MAX_ROW_PARAMS) {
                document->row_overflow = 1U;
            } else {
                struct xml_row_param *record =
                    &document->row_params[document->row_param_count++];
                strcpy(record->table_id, document->current_table_id);
                strcpy(record->parameter, parameter->id);
                strcpy(record->structure, parameter->structure);
                strcpy(record->value, frame->text);
                record->row = (unsigned int)document->current_row_index;
                if (document->depth >= 3U) {
                    const struct frame *row = &document->stack[document->depth - 3U];
                    record->direct_row_child =
                        strcmp(row->name, "section") == 0 &&
                        strcmp(row->structure, "row") == 0;
                }
            }
        }
    }
    if (strcmp(name, "option") == 0 && document->depth >= 2U &&
        strcmp(document->stack[document->depth - 2U].name, "parameter") == 0 &&
        has_ancestor(document, "payload")) {
        const char *form = ancestor_form_id(document);
        const struct frame *parameter = &document->stack[document->depth - 2U];
        struct option_value *record;
        if (form == NULL || form[0] == '\0' || strlen(form) > XML_MAX_NAME ||
            parameter->id[0] == '\0' || strlen(parameter->id) > XML_MAX_NAME ||
            frame->text_length >= sizeof(record->value) ||
            document->option_value_count >= PM3000_FIXED_MAX_CHOICES + 1U)
            return -1;
        record = &document->option_values[document->option_value_count++];
        strcpy(record->form, form);
        strcpy(record->parameter, parameter->id);
        strcpy(record->value, frame->text);
    }
    if (document->depth == 2U && strcmp(name, "action") == 0) {
        if (++document->actions != 1U) return -1;
        strcpy(document->action, frame->text);
    } else if (document->depth == 2U && strcmp(name, "sid") == 0) {
        if (++document->sids != 1U || frame->text_length == 0U ||
            frame->text_length > 128U) return -1;
        strcpy(document->sid, frame->text);
    } else if (document->depth == 3U && strcmp(name, "path") == 0 &&
               ancestor_is(document, 2U, "paths") &&
               ancestor_is(document, 3U, "avtrans")) {
        if (++document->paths != 1U) return -1;
        strcpy(document->path, frame->text);
    }
    if (strcmp(name, "section") == 0 &&
        strcmp(frame->structure, "row") == 0 &&
        document->current_row_index >= 0) {
        ++document->table_row_count;
        document->current_row_index = -1;
    }
    if (strcmp(name, "section") == 0 &&
        strcmp(frame->structure, "table") == 0 &&
        strcmp(frame->id, document->current_table_id) == 0) {
        document->current_table_id[0] = '\0';
    }
    --document->depth;
    return 0;
}

static int fixed_attribute_allowed(const char *element, const char *attribute) {
    if (strcmp(element, "control") == 0 || strcmp(element, "section") == 0 ||
        strcmp(element, "parameter") == 0)
        return strcmp(attribute, "id") == 0 || strcmp(attribute, "structure") == 0 ||
               (strcmp(element, "parameter") == 0 && strcmp(attribute, "value") == 0);
    if (strcmp(element, "option") == 0) return strcmp(attribute, "label") == 0;
    return 0;
}

static int start_element(struct document *document, int *self_closing) {
    struct frame *frame;
    char attribute_names[XML_MAX_ATTRS][XML_MAX_NAME + 1U];
    char id[XML_MAX_TEXT + 1U] = {0};
    char path[XML_MAX_TEXT + 1U] = {0};
    char access_path[XML_MAX_TEXT + 1U] = {0};
    char access_rights[XML_MAX_NAME + 1U] = {0};
    char structure[XML_MAX_NAME + 1U] = {0};
    char parameter_value[33] = {0};
    unsigned int attribute_count = 0U;
    if (document->depth >= XML_MAX_DEPTH) return -1;
    frame = &document->stack[document->depth];
    memset(frame, 0, sizeof(*frame));
    if (parse_name(document, frame->name, sizeof(frame->name)) != 0) return -1;
    while (1) {
        char name[XML_MAX_NAME + 1U];
        char value[XML_MAX_TEXT + 1U];
        unsigned int index;
        size_t separator_start = document->offset;
        skip_space(document);
        if (document->offset >= document->length) return -1;
        if (document->input[document->offset] == '>') {
            ++document->offset; *self_closing = 0; break;
        }
        if (document->input[document->offset] == '/' &&
            document->offset + 1U < document->length &&
            document->input[document->offset + 1U] == '>') {
            document->offset += 2U; *self_closing = 1; break;
        }
        if (document->offset == separator_start || attribute_count >= XML_MAX_ATTRS ||
            parse_name(document, name, sizeof(name)) != 0) return -1;
        for (index = 0U; index < attribute_count; ++index)
            if (strcmp(attribute_names[index], name) == 0) return -1;
        strcpy(attribute_names[attribute_count++], name);
        skip_space(document);
        if (document->offset >= document->length ||
            document->input[document->offset++] != '=') return -1;
        skip_space(document);
        if (attribute_value(document, value, sizeof(value)) != 0) return -1;
        if (strcmp(name, "id") == 0) strcpy(id, value);
        else if (strcmp(name, "path") == 0) strcpy(path, value);
        else if (strcmp(name, "accessPath") == 0) strcpy(access_path, value);
        else if (strcmp(name, "accessRights") == 0) {
            if (strlen(value) > XML_MAX_NAME) return -1;
            strcpy(access_rights, value);
        }
        else if (strcmp(name, "structure") == 0) {
            if (strlen(value) > XML_MAX_NAME) return -1;
            strcpy(structure, value);
        }
        else if (strcmp(name, "value") == 0) {
            if (strlen(value) >= sizeof(parameter_value)) return -1;
            strcpy(parameter_value, value);
        }
    }
    {
        unsigned int index;
        for (index = 0U; index < attribute_count; ++index)
            if (!fixed_attribute_allowed(frame->name, attribute_names[index]))
                ++document->unexpected_fixed_attributes;
    }
    if (document->depth == 0U) {
        if (strcmp(frame->name, "avtrans") != 0 || ++document->roots != 1U) return -1;
    } else if (strcmp(frame->name, "error") == 0) {
        ++document->errors;
    }
    if (document->depth == 1U && strcmp(frame->name, "payload") == 0) {
        if (++document->payloads != 1U) return -1;
        strcpy(document->payload_structure, structure);
    }
    strcpy(frame->id, id);
    strcpy(frame->structure, structure);
    strcpy(frame->path, path);
    strcpy(frame->access_path, access_path);
    strcpy(frame->access_rights, access_rights);
    strcpy(frame->attribute_value, parameter_value);
    if (document->depth == 1U) {
        unsigned int expected = document->fixed_envelope_stage;
        if ((expected == 0U && strcmp(frame->name, "action") == 0) ||
            (expected == 1U && strcmp(frame->name, "paths") == 0) ||
            (expected == 2U && strcmp(frame->name, "payload") == 0))
            ++document->fixed_envelope_stage;
        else
            ++document->unexpected_fixed_sequence;
    }
    if (document->depth == 2U && strcmp(document->stack[1].name, "payload") == 0) {
        unsigned int expected = document->fixed_payload_stage;
        if ((expected == 0U && strcmp(frame->name, "controls") == 0) ||
            (expected == 1U && strcmp(frame->name, "section") == 0))
            ++document->fixed_payload_stage;
        else
            ++document->unexpected_fixed_sequence;
    }
    if (document->depth > 0U && strcmp(document->stack[document->depth - 1U].name, "parameter") == 0) {
        struct frame *parameter = &document->stack[document->depth - 1U];
        if (strcmp(frame->name, "value") == 0) {
            if (parameter->fixed_child_stage != 0U) ++document->unexpected_fixed_sequence;
            parameter->fixed_child_stage = 1U;
        } else if (strcmp(frame->name, "option") == 0) {
            if (parameter->fixed_child_stage == 0U) ++document->unexpected_fixed_sequence;
            parameter->fixed_child_stage = 2U;
        }
    }
    if (document->depth > 0U && !has_ancestor(document, "payload")) {
        const struct frame *container = &document->stack[document->depth - 1U];
        int allowed =
            (document->depth == 1U &&
             (strcmp(frame->name, "action") == 0 ||
              strcmp(frame->name, "paths") == 0 ||
              strcmp(frame->name, "payload") == 0)) ||
            (document->depth == 2U && strcmp(container->name, "paths") == 0 &&
             strcmp(frame->name, "path") == 0);
        if (!allowed) ++document->unexpected_envelope_elements;
    }
    if (has_ancestor(document, "payload")) {
        const struct frame *container = document->depth == 0U ? NULL :
                                        &document->stack[document->depth - 1U];
        if (strcmp(frame->name, "section") == 0) {
            ++document->payload_section_count;
            if (strcmp(structure, "form") == 0 && container != NULL &&
                strcmp(container->name, "payload") == 0)
                ++document->direct_payload_forms;
        } else if (strcmp(frame->name, "value") == 0) {
            ++document->payload_value_count;
        } else if (strcmp(frame->name, "option") == 0) {
            ++document->payload_option_count;
        } else if (strcmp(frame->name, "controls") == 0) {
            if (container != NULL && strcmp(container->name, "payload") == 0)
                ++document->direct_payload_controls;
            else
                ++document->unexpected_payload_elements;
        } else if (strcmp(frame->name, "control") == 0) {
            if (container == NULL || strcmp(container->name, "controls") != 0 ||
                document->depth < 2U ||
                strcmp(document->stack[document->depth - 2U].name, "payload") != 0)
                ++document->unexpected_payload_elements;
        } else if (strcmp(frame->name, "parameter") != 0)
            ++document->unexpected_payload_elements;
    }
    if (strcmp(frame->name, "parameter") == 0 && has_ancestor(document, "payload")) {
        const char *form = ancestor_form_id(document);
        if (++document->payload_parameter_count > XML_MAX_PARAMETERS) return -1;
        if (form != NULL) {
            struct parameter_declaration *record;
            const struct frame *container;
            if (form[0] == '\0' || document->depth == 0U ||
                document->parameter_declaration_count >= XML_MAX_PARAMETERS) return -1;
            if (id[0] == '\0' && !(strcmp(structure, "radio") == 0 &&
                                   parameter_value[0] != '\0')) return -1;
            record = &document->parameter_declarations[document->parameter_declaration_count++];
            container = &document->stack[document->depth - 1U];
            strcpy(record->form, form);
            strcpy(record->parameter, id);
            strcpy(record->structure, structure);
            strcpy(record->container_name, container->name);
            strcpy(record->container_id, container->id);
            strcpy(record->container_structure, container->structure);
            strcpy(record->container_attribute_value, container->attribute_value);
            record->direct_form_child =
                strcmp(container->name, "section") == 0 &&
                strcmp(container->id, form) == 0 &&
                strcmp(container->structure, "form") == 0;
            strcpy(record->attribute_value, parameter_value);
        }
    }
    if (document->depth == 2U && strcmp(frame->name, "section") == 0 &&
        strcmp(id, "changedPassword") == 0 && strcmp(structure, "standard") == 0 &&
        strcmp(document->stack[1].name, "payload") == 0)
        ++document->password_changed_section;
    else if (document->depth == 3U && strcmp(frame->name, "section") == 0 &&
             strcmp(id, "infoForm") == 0 && strcmp(structure, "form") == 0 &&
             strcmp(document->stack[2].name, "section") == 0 &&
             strcmp(document->stack[2].id, "changedPassword") == 0 &&
             strcmp(document->stack[2].structure, "standard") == 0)
        ++document->password_info_form;
    else if (document->depth == 4U && strcmp(frame->name, "parameter") == 0 &&
             strcmp(id, "title") == 0 && strcmp(structure, "title") == 0 &&
             strcmp(document->stack[3].name, "section") == 0 &&
             strcmp(document->stack[3].id, "infoForm") == 0 &&
             strcmp(document->stack[3].structure, "form") == 0)
        ++document->password_title;
    else if (document->depth == 5U && strcmp(frame->name, "parameter") == 0 &&
             strcmp(id, "message") == 0 && strcmp(structure, "notice") == 0 &&
             strcmp(document->stack[4].name, "parameter") == 0 &&
             strcmp(document->stack[4].id, "title") == 0 &&
             strcmp(document->stack[4].structure, "title") == 0)
        ++document->password_message;
    if (strcmp(frame->name, "section") == 0 && strcmp(structure, "nav") == 0 &&
        path[0] != '\0' && has_ancestor(document, "payload")) {
        if (remember_navigation_path(document, path) != 0) return -1;
        if (strcmp(path, "units.applianceSettings.help") == 0 &&
            strcmp(access_path, "configuration.appliance.language") == 0 &&
            strcmp(access_rights, "w") == 0)
            document->help_language_capability = 1U;
        if (strcmp(path, "units.applianceSettings.date_and_time.time_zone") == 0) {
            size_t ancestor;
            for (ancestor = 0U; ancestor < document->depth; ++ancestor) {
                const struct frame *candidate = &document->stack[ancestor];
                if (strcmp(candidate->path, "units.applianceSettings.date_and_time") == 0 &&
                    strcmp(candidate->access_path, "management.date") == 0 &&
                    strcmp(candidate->access_rights, "w") == 0)
                    document->time_zone_capability = 1U;
            }
        }
        if (strcmp(path, "units.event_notification.global_settings_databuffering") == 0 ||
            strcmp(path, "units.event_notification.sessions") == 0) {
            size_t ancestor;
            for (ancestor = 0U; ancestor < document->depth; ++ancestor) {
                const struct frame *candidate = &document->stack[ancestor];
                if (strcmp(candidate->path, "units.event_notification") == 0 &&
                    strcmp(candidate->access_path, "configuration.event-notify") == 0 &&
                    strcmp(candidate->access_rights, "w") == 0) {
                    if (strcmp(path, "units.event_notification.global_settings_databuffering") == 0)
                        document->data_buffering_capability = 1U;
                    else
                        document->appliance_logging_capability = 1U;
                }
            }
        }
    }
    if (strcmp(frame->name, "section") == 0 && strcmp(structure, "form") == 0 &&
        has_ancestor(document, "payload")) {
        if (id[0] == '\0' || document->form_count >= 32U) return -1;
        strcpy(document->form_ids[document->form_count++], id);
    }
    if (strcmp(frame->name, "control") == 0 && has_ancestor(document, "controls") &&
        has_ancestor(document, "payload")) {
        ++document->control_count;
        if (strcmp(id, "save") == 0 && strcmp(structure, "button") == 0 &&
            document->depth >= 2U &&
            strcmp(document->stack[document->depth - 1U].name, "controls") == 0 &&
            strcmp(document->stack[document->depth - 2U].name, "payload") == 0)
            ++document->save_controls;
        if (strcmp(id, "targPowerOn") == 0) {
            document->power_on = 1U;
        } else if (strcmp(id, "targPowerOff") == 0) {
            document->power_off = 1U;
        } else if (strcmp(id, "targCycle") == 0) {
            document->power_cycle = 1U;
        }
    }
    if (strcmp(frame->name, "section") == 0 &&
        strcmp(structure, "table") == 0 &&
        id[0] != '\0' && strlen(id) <= XML_MAX_NAME &&
        has_ancestor(document, "payload")) {
        ++document->table_count;
        strcpy(document->table_id, id);
        strcpy(document->current_table_id, id);
    }
    if (strcmp(frame->name, "section") == 0 &&
        strcmp(structure, "row") == 0 && has_ancestor(document, "payload")) {
        if (document->current_table_id[0] != '\0' &&
            document->depth > 0U &&
            strcmp(document->stack[document->depth - 1U].name, "section") == 0 &&
            strcmp(document->stack[document->depth - 1U].structure, "table") == 0 &&
            strcmp(document->stack[document->depth - 1U].id,
                   document->current_table_id) == 0) {
            document->current_row_index = (int)document->table_row_count;
        } else {
            ++document->unexpected_table_rows;
        }
    }
    ++document->depth;
    if (*self_closing && close_element(document, frame->name) != 0) return -1;
    return 0;
}

static int parse_document(const unsigned char *xml, size_t length,
                          struct document *document) {
    /* A CGI process handles one request, so keeping this bounded parser workspace
       outside the call stack is safe and avoids exhausting legacy stack limits. */
    static struct option_value option_values[PM3000_FIXED_MAX_CHOICES + 1U];
    memset(document, 0, sizeof(*document));
    document->option_values = option_values;
    document->current_row_index = -1;
    if (xml == NULL || length == 0U || length > XML_MAX_BYTES ||
        !valid_utf8(xml, length)) return -1;
    document->input = xml;
    document->length = length;
    while (document->offset < document->length) {
        if (document->input[document->offset] != '<') {
            size_t start = document->offset;
            size_t index;
            while (document->offset < document->length &&
                   document->input[document->offset] != '<') ++document->offset;
            for (index = start; index + 2U < document->offset; ++index)
                if (document->input[index] == ']' &&
                    document->input[index + 1U] == ']' &&
                    document->input[index + 2U] == '>') return -1;
            if (document->depth == 0U) {
                for (index = start; index < document->offset; ++index)
                    if (!isspace((unsigned char)document->input[index])) return -1;
            } else {
                struct frame *frame = &document->stack[document->depth - 1U];
                if (!has_ancestor(document, "payload") &&
                    !((document->depth == 2U &&
                       (strcmp(frame->name, "action") == 0 || strcmp(frame->name, "sid") == 0)) ||
                      (document->depth == 3U && strcmp(frame->name, "path") == 0 &&
                       ancestor_is(document, 2U, "paths")))) {
                    for (index = start; index < document->offset; ++index) {
                        unsigned char byte = document->input[index];
                        if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r') {
                            ++document->unexpected_envelope_text;
                            break;
                        }
                    }
                }
                if (has_ancestor(document, "payload") &&
                    strcmp(frame->name, "value") != 0 &&
                    strcmp(frame->name, "option") != 0) {
                    for (index = start; index < document->offset; ++index) {
                        unsigned char byte = document->input[index];
                        if (byte != ' ' && byte != '\t' && byte != '\n' && byte != '\r') {
                            ++document->unexpected_payload_text;
                            break;
                        }
                    }
                }
                if ((document->depth == 2U &&
                     (strcmp(frame->name, "action") == 0 ||
                      strcmp(frame->name, "sid") == 0)) ||
                    (document->depth == 3U && strcmp(frame->name, "path") == 0 &&
                     ancestor_is(document, 2U, "paths")) ||
                    (((strcmp(frame->name, "value") == 0 ||
                       strcmp(frame->name, "option") == 0)) &&
                     (ancestor_form_id(document) != NULL ||
                      document->current_row_index >= 0))) {
                    if (decode(document->input + start, document->offset - start,
                               frame->text, &frame->text_length,
                               sizeof(frame->text)) != 0) return -1;
                }
            }
            continue;
        }
        ++document->offset;
        if (document->offset >= document->length) return -1;
        if (document->input[document->offset] == '?') {
            size_t content_start, end;
            content_start = document->offset + 1U;
            end = content_start;
            while (end + 1U < document->length &&
                   !(document->input[end] == '?' && document->input[end + 1U] == '>')) ++end;
            if (end + 1U >= document->length) return -1;
            if (document->offset == 1U) {
                if (!valid_xml_declaration(document->input + content_start,
                                           end - content_start)) return -1;
            } else if (document->depth == 0U && document->roots == 0U &&
                       document->vendor_stylesheets == 0U &&
                       valid_vendor_stylesheet(document->input + content_start,
                                               end - content_start)) {
                ++document->vendor_stylesheets;
            } else return -1;
            document->offset = end + 2U;
        } else if (document->input[document->offset] == '!') {
            return -1;
        } else if (document->input[document->offset] == '/') {
            char name[XML_MAX_NAME + 1U];
            ++document->offset;
            if (parse_name(document, name, sizeof(name)) != 0) return -1;
            skip_space(document);
            if (document->offset >= document->length ||
                document->input[document->offset++] != '>' ||
                close_element(document, name) != 0) return -1;
        } else {
            int self_closing;
            if (start_element(document, &self_closing) != 0) return -1;
        }
    }
    return document->depth == 0U && document->roots == 1U &&
           document->actions == 1U && document->paths == 1U &&
           document->errors == 0U ? 0 : -1;
}

int pm3000_xml_login_sid(const unsigned char *xml, size_t length,
                         char sid[129]) {
    struct document document;
    if (parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "header") != 0 ||
        strcmp(document.path, "units") != 0 || document.sids != 1U ||
        document.payloads != 1U || strcmp(document.payload_structure, "header") != 0)
        return -1;
    strcpy(sid, document.sid);
    return 0;
}

int pm3000_xml_navigation(const unsigned char *xml, size_t length,
                          const char *const *allowed_paths,
                          unsigned int allowed_count, uint64_t *path_mask,
                          int *can_manage, int *can_help_language,
                          int *can_data_buffering,
                          int *can_appliance_logging,
                          int *can_time_zone) {
    struct document document;
    unsigned int index, candidate;
    if (allowed_count > 64U || parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "navigation") != 0 ||
        strcmp(document.path, "units") != 0 || document.payloads != 1U ||
        strcmp(document.payload_structure, "navigation") != 0) return -1;
    *path_mask = 0U;
    for (candidate = 0U; candidate < document.navigation_count; ++candidate) {
        for (index = 0U; index < allowed_count; ++index) {
            if (strcmp(document.navigation_paths[candidate], allowed_paths[index]) == 0)
                *path_mask |= UINT64_C(1) << index;
        }
    }
    *can_manage = 0;
    for (candidate = 0U; candidate < document.navigation_count; ++candidate)
        if (strcmp(document.navigation_paths[candidate],
                   "units.users.local_accounts.user_names") == 0) *can_manage = 1;
    *can_help_language = document.help_language_capability == 1U;
    *can_data_buffering = document.data_buffering_capability == 1U;
    *can_appliance_logging = document.appliance_logging_capability == 1U;
    *can_time_zone = document.time_zone_capability == 1U;
    return 0;
}

int pm3000_xml_topology_controls(const unsigned char *xml, size_t length,
                                 int *can_control) {
    struct document document;
    if (parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 ||
        strcmp(document.path, "units.topology") != 0 || document.payloads != 1U)
        return -1;
    *can_control = document.power_on == 1U && document.power_off == 1U &&
                   document.power_cycle == 1U;
    return 0;
}

int pm3000_xml_confirm(const unsigned char *xml, size_t length,
                       const char *action, const char *path) {
    struct document document;
    return parse_document(xml, length, &document) == 0 &&
           strcmp(document.action, action) == 0 &&
           strcmp(document.path, path) == 0;
}

int pm3000_xml_content_result(const unsigned char *xml, size_t length,
                              const char *path) {
    struct document document;
    return parse_document(xml, length, &document) == 0 &&
           strcmp(document.action, "content") == 0 &&
           strcmp(document.path, path) == 0 && document.payloads == 1U;
}

int pm3000_xml_password_changed(const unsigned char *xml, size_t length) {
    struct document document;
    return parse_document(xml, length, &document) == 0 &&
           strcmp(document.action, "content") == 0 &&
           strcmp(document.path, "units.change_password.changedPassword") == 0 &&
           document.payloads == 1U && document.password_changed_section == 1U &&
           document.password_info_form == 1U && document.password_title == 1U &&
           document.password_message == 1U;
}

int pm3000_xml_form_value(const unsigned char *xml, size_t length,
                           const char *path, const char *form,
                           const char *parameter, char *value,
                           size_t value_size) {
    struct document document;
    unsigned int index, matches = 0U;
    const char *selected = NULL;
    if (value_size == 0U || parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 ||
        strcmp(document.path, path) != 0 || document.payloads != 1U)
        return -1;
    for (index = 0U; index < document.parameter_value_count; ++index) {
        const struct parameter_value *record = &document.parameter_values[index];
        if (strcmp(record->form, form) != 0 ||
            strcmp(record->parameter, parameter) != 0) continue;
        if (++matches != 1U) return -1;
        selected = record->value;
    }
    if (matches != 1U || selected == NULL || strlen(selected) >= value_size)
        return -1;
    strcpy(value, selected);
    return 0;
}

int pm3000_xml_boolean_form_value(const unsigned char *xml, size_t length,
                                  const char *path, const char *form,
                                  const char *parameter, int *value) {
    char parsed[6];
    if (pm3000_xml_form_value(xml, length, path, form, parameter,
                              parsed, sizeof(parsed)) != 0) return -1;
    if (strcmp(parsed, "true") == 0) *value = 1;
    else if (strcmp(parsed, "false") == 0) *value = 0;
    else return -1;
    return 0;
}

int pm3000_xml_dsview_value(const unsigned char *xml, size_t length,
                            const char *path, int *value) {
    struct document document;
    unsigned int index, matches = 0U;
    const struct parameter_value *selected = NULL;
    if (parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 ||
        strcmp(document.path, path) != 0 || document.payloads != 1U) return -1;
    for (index = 0U; index < document.parameter_value_count; ++index) {
        const struct parameter_value *record = &document.parameter_values[index];
        if (strcmp(record->form, "dsviewControl") != 0 ||
            strcmp(record->parameter, "allowDSView") != 0) continue;
        if (++matches != 1U) return -1;
        selected = record;
    }
    if (matches != 1U || selected == NULL ||
        strcmp(selected->structure, "checkbox") != 0 ||
        strcmp(selected->container_name, "parameter") != 0 ||
        strcmp(selected->container_id, "dsview") != 0 ||
        strcmp(selected->container_structure, "title") != 0) return -1;
    if (strcmp(selected->value, "true") == 0) *value = 1;
    else if (strcmp(selected->value, "false") == 0) *value = 0;
    else return -1;
    return 0;
}

int pm3000_xml_system_information(const unsigned char *xml, size_t length,
                                   struct pm3000_sysinfo *out) {
    struct document document;
    unsigned int index;
    unsigned int found_model = 0U, found_boot = 0U, found_firmware = 0U;
    unsigned int found_booted = 0U, found_cpu = 0U, found_rev = 0U, found_bogo = 0U;
    if (parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 ||
        strcmp(document.path, "units.applianceSettings.information") != 0 ||
        document.payloads != 1U) return -1;
    for (index = 0U; index < document.parameter_value_count; ++index) {
        const struct parameter_value *record = &document.parameter_values[index];
        const char *expected_container = NULL;
        if (strcmp(record->form, "identityform") != 0) continue;
        if (strcmp(record->parameter, "modelnumber") == 0)
            expected_container = "identity";
        else if (strcmp(record->parameter, "bootcodeversion") == 0 ||
                 strcmp(record->parameter, "firmwareversion") == 0 ||
                 strcmp(record->parameter, "bootedFrom") == 0)
            expected_container = "version";
        else if (strcmp(record->parameter, "cpu") == 0 ||
                 strcmp(record->parameter, "revision") == 0 ||
                 strcmp(record->parameter, "bogomips") == 0)
            expected_container = "cpuinfo";
        if (expected_container != NULL &&
            (strcmp(record->structure, "ROtext") != 0 ||
             strcmp(record->container_name, "parameter") != 0 ||
             strcmp(record->container_id, expected_container) != 0 ||
             strcmp(record->container_structure, "title") != 0)) return -1;
        if (strcmp(record->parameter, "modelnumber") == 0) {
            if (++found_model != 1U || strlen(record->value) >= sizeof(out->model_number)) return -1;
            strcpy(out->model_number, record->value);
        } else if (strcmp(record->parameter, "bootcodeversion") == 0) {
            if (++found_boot != 1U || strlen(record->value) >= sizeof(out->boot_code_version)) return -1;
            strcpy(out->boot_code_version, record->value);
        } else if (strcmp(record->parameter, "firmwareversion") == 0) {
            if (++found_firmware != 1U || strlen(record->value) >= sizeof(out->firmware_version)) return -1;
            strcpy(out->firmware_version, record->value);
        } else if (strcmp(record->parameter, "bootedFrom") == 0) {
            if (++found_booted != 1U || strlen(record->value) >= sizeof(out->booted_from)) return -1;
            strcpy(out->booted_from, record->value);
        } else if (strcmp(record->parameter, "cpu") == 0) {
            if (++found_cpu != 1U || strlen(record->value) >= sizeof(out->cpu)) return -1;
            strcpy(out->cpu, record->value);
        } else if (strcmp(record->parameter, "revision") == 0) {
            if (++found_rev != 1U || strlen(record->value) >= sizeof(out->revision)) return -1;
            strcpy(out->revision, record->value);
        } else if (strcmp(record->parameter, "bogomips") == 0) {
            if (++found_bogo != 1U || strlen(record->value) >= sizeof(out->bogomips)) return -1;
            strcpy(out->bogomips, record->value);
        }
    }
    if (found_model != 1U || found_boot != 1U || found_firmware != 1U ||
        found_booted != 1U || found_cpu != 1U || found_rev != 1U || found_bogo != 1U) return -1;
    return 0;
}

int pm3000_xml_nis_values(const unsigned char *xml, size_t length,
                          const char *path, char *domain, size_t domain_size,
                          char *address, size_t address_size) {
    struct document document;
    unsigned int index, found = 0U;
    if (domain_size == 0U || address_size == 0U ||
        parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 ||
        strcmp(document.path, path) != 0 || document.payloads != 1U) return -1;
    for (index = 0U; index < document.parameter_value_count; ++index) {
        const struct parameter_value *record = &document.parameter_values[index];
        const char *expected;
        char *output;
        size_t capacity;
        if (strcmp(record->form, "nisserver") != 0) continue;
        if (found >= 2U) return -1;
        expected = found == 0U ? "domainname" : "address";
        output = found == 0U ? domain : address;
        capacity = found == 0U ? domain_size : address_size;
        if (strcmp(record->parameter, expected) != 0 ||
            strcmp(record->structure, "text") != 0 ||
            !record->direct_form_child || strlen(record->value) >= capacity) return -1;
        strcpy(output, record->value);
        ++found;
    }
    return found == 2U ? 0 : -1;
}

int pm3000_xml_fixed_form(const unsigned char *xml, size_t length,
                          const char *path, const char *form,
                          const struct pm3000_xml_fixed_field *fields,
                          unsigned int field_count,
                          const struct pm3000_xml_fixed_parameter *parameters,
                          unsigned int parameter_count, uint32_t choice_field_mask,
                          struct pm3000_xml_fixed_result *out) {
    struct document document;
    unsigned int index, field_index, next_field = 0U, matching_forms = 0U;
    unsigned int seen[PM3000_FIXED_MAX_FIELDS] = {0};
    if (out == NULL || fields == NULL || parameters == NULL ||
        field_count == 0U || parameter_count == 0U ||
        field_count > PM3000_FIXED_MAX_FIELDS || parameter_count > XML_MAX_PARAMETERS ||
        (field_count < 32U && (choice_field_mask >> field_count) != 0U) ||
        parse_document(xml, length, &document) != 0 ||
        strcmp(document.action, "content") != 0 || strcmp(document.path, path) != 0 ||
        document.payloads != 1U || document.form_count != 1U ||
        document.payload_section_count != 1U || document.direct_payload_forms != 1U ||
        document.direct_payload_controls != 1U || document.unexpected_payload_elements != 0U ||
        document.unexpected_payload_text != 0U || document.unexpected_envelope_elements != 0U ||
        document.unexpected_envelope_text != 0U || document.unexpected_fixed_attributes != 0U ||
        document.unexpected_fixed_sequence != 0U || document.fixed_envelope_stage != 3U ||
        document.fixed_payload_stage != 2U ||
        document.payload_value_count != field_count ||
        document.payload_option_count != document.option_value_count ||
        document.control_count != 1U || document.save_controls != 1U) return -1;
    memset(out, 0, sizeof(*out));
    for (index = 0U; index < document.form_count; ++index)
        if (strcmp(document.form_ids[index], form) == 0) ++matching_forms;
    if (matching_forms != 1U || document.payload_parameter_count != parameter_count ||
        document.parameter_declaration_count != parameter_count)
        return -1;
    for (index = 0U; index < parameter_count; ++index) {
        const struct parameter_declaration *record = &document.parameter_declarations[index];
        const struct pm3000_xml_fixed_parameter *expected = &parameters[index];
        const char *parent_structure = expected->parent_structure == NULL ? "title" : expected->parent_structure;
        if (strcmp(record->form, form) != 0 ||
            strcmp(record->structure, expected->structure) != 0) return -1;
        if (expected->id[0] == '@') {
            if (record->parameter[0] != '\0' ||
                strcmp(record->attribute_value, expected->id + 1) != 0) return -1;
        } else if (strcmp(record->parameter, expected->id) != 0 ||
                   record->attribute_value[0] != '\0') return -1;
        if (expected->parent_id == NULL) {
            if (!record->direct_form_child) return -1;
        } else if (strcmp(record->container_name, "parameter") != 0 ||
                   strcmp(record->container_structure, parent_structure) != 0 ||
                   (expected->parent_id[0] == '@' ?
                    (record->container_id[0] != '\0' ||
                     strcmp(record->container_attribute_value, expected->parent_id + 1) != 0) :
                    (strcmp(record->container_id, expected->parent_id) != 0 ||
                     record->container_attribute_value[0] != '\0'))) return -1;
    }
    for (index = 0U; index < document.parameter_value_count; ++index) {
        const struct parameter_value *record = &document.parameter_values[index];
        const char *parent_structure;
        if (strcmp(record->form, form) != 0) continue;
        for (field_index = 0U; field_index < field_count; ++field_index)
            if (strcmp(record->parameter, fields[field_index].id) == 0) break;
        if (field_index == field_count) return -1;
        if (field_index != next_field || ++seen[field_index] != 1U ||
            strcmp(record->structure, fields[field_index].structure) != 0 ||
            strlen(record->value) >= sizeof(out->values[field_index])) return -1;
        parent_structure = fields[field_index].parent_structure == NULL ? "title" : fields[field_index].parent_structure;
        if (fields[field_index].parent_id == NULL) {
            if (!record->direct_form_child) return -1;
        } else if (strcmp(record->container_name, "parameter") != 0 ||
                   strcmp(record->container_structure, parent_structure) != 0 ||
                   (fields[field_index].parent_id[0] == '@' ?
                    (record->container_id[0] != '\0' ||
                     strcmp(record->container_attribute_value,
                            fields[field_index].parent_id + 1) != 0) :
                    (strcmp(record->container_id, fields[field_index].parent_id) != 0 ||
                     record->container_attribute_value[0] != '\0'))) return -1;
        strcpy(out->values[field_index], record->value);
        ++next_field;
    }
    if (next_field != field_count) return -1;
    if (choice_field_mask != 0U) {
        uint32_t seen_choice_fields = 0U;
        for (index = 0U; index < document.option_value_count; ++index) {
            const struct option_value *option = &document.option_values[index];
            unsigned int previous, option_field;
            if (strcmp(option->form, form) != 0) continue;
            for (option_field = 0U; option_field < field_count; ++option_field)
                if (strcmp(option->parameter, fields[option_field].id) == 0) break;
            if (option_field == field_count ||
                (choice_field_mask & (UINT32_C(1) << option_field)) == 0U) return -1;
            if (option->value[0] == '\0' || strlen(option->value) >= sizeof(out->choices[0]) ||
                out->choice_count >= PM3000_FIXED_MAX_CHOICES) return -1;
            for (previous = 0U; previous < out->choice_count; ++previous)
                if (out->choice_fields[previous] == option_field &&
                    strcmp(out->choices[previous], option->value) == 0) return -1;
            out->choice_fields[out->choice_count] = (unsigned char)option_field;
            strcpy(out->choices[out->choice_count++], option->value);
            seen_choice_fields |= UINT32_C(1) << option_field;
        }
        if (seen_choice_fields != choice_field_mask) return -1;
    }
    return 0;
}

static int table_parse_start(const unsigned char *xml, size_t length,
                              const char *path, const char *table_id,
                              struct document *document) {
    if (parse_document(xml, length, document) != 0 ||
        strcmp(document->action, "content") != 0 ||
        strcmp(document->path, path) != 0 ||
        document->payloads != 1U || document->row_overflow ||
        document->unexpected_table_rows != 0U ||
        document->table_count != 1U ||
        strcmp(document->table_id, table_id) != 0) return -1;
    if (document->table_row_count > PM3000_MAX_TABLE_ROWS) return -1;
    return 0;
}

static int valid_row_parameter(const struct xml_row_param *parameter) {
    return parameter->direct_row_child &&
           strcmp(parameter->structure, "ROtext") == 0;
}

int pm3000_xml_memory_table(const unsigned char *xml, size_t length,
                             struct pm3000_memory_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_name[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_value[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.applianceSettings.usage.memory",
                          "memoryTable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "memoryTable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "memoryFieldName") == 0) {
            if (++found_name[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].name)) return -1;
            strcpy(out->rows[r].name, p->value);
        } else if (strcmp(p->parameter, "memoryFieldValue") == 0) {
            if (++found_value[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].value)) return -1;
            strcpy(out->rows[r].value, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_name[i] != 1U || found_value[i] != 1U) return -1;
    return 0;
}

int pm3000_xml_flash_table(const unsigned char *xml, size_t length,
                            struct pm3000_flash_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_fs[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_blk[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_used[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_avail[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_pct[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_mnt[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.applianceSettings.usage.flashUsage",
                          "flashUsageTable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "flashUsageTable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "filesystem") == 0) {
            if (++found_fs[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].filesystem)) return -1;
            strcpy(out->rows[r].filesystem, p->value);
        } else if (strcmp(p->parameter, "1kBlocks") == 0) {
            if (++found_blk[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].blocks1k)) return -1;
            strcpy(out->rows[r].blocks1k, p->value);
        } else if (strcmp(p->parameter, "used") == 0) {
            if (++found_used[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].used)) return -1;
            strcpy(out->rows[r].used, p->value);
        } else if (strcmp(p->parameter, "available") == 0) {
            if (++found_avail[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].available)) return -1;
            strcpy(out->rows[r].available, p->value);
        } else if (strcmp(p->parameter, "usePercentage") == 0) {
            if (++found_pct[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].use_percentage)) return -1;
            strcpy(out->rows[r].use_percentage, p->value);
        } else if (strcmp(p->parameter, "mountedOn") == 0) {
            if (++found_mnt[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].mounted_on)) return -1;
            strcpy(out->rows[r].mounted_on, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_fs[i] != 1U || found_blk[i] != 1U || found_used[i] != 1U ||
            found_avail[i] != 1U || found_pct[i] != 1U || found_mnt[i] != 1U) return -1;
    return 0;
}

int pm3000_xml_netdev_table(const unsigned char *xml, size_t length,
                             struct pm3000_netdev_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_name[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_stat[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ip4a[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ip4m[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ip6a[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.monitoring.networkmon.monitoringDevice",
                          "devicesTable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "devicesTable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "deviceName") == 0) {
            if (++found_name[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].device_name)) return -1;
            strcpy(out->rows[r].device_name, p->value);
        } else if (strcmp(p->parameter, "status") == 0) {
            if (++found_stat[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].status)) return -1;
            strcpy(out->rows[r].status, p->value);
        } else if (strcmp(p->parameter, "ipv4address") == 0) {
            if (++found_ip4a[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].ipv4_address)) return -1;
            strcpy(out->rows[r].ipv4_address, p->value);
        } else if (strcmp(p->parameter, "ipv4mask") == 0) {
            if (++found_ip4m[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].ipv4_mask)) return -1;
            strcpy(out->rows[r].ipv4_mask, p->value);
        } else if (strcmp(p->parameter, "ipv6address") == 0) {
            if (++found_ip6a[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].ipv6_address)) return -1;
            strcpy(out->rows[r].ipv6_address, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_name[i] != 1U || found_stat[i] != 1U || found_ip4a[i] != 1U ||
            found_ip4m[i] != 1U || found_ip6a[i] != 1U) return -1;
    return 0;
}

int pm3000_xml_route4_table(const unsigned char *xml, size_t length,
                             struct pm3000_route4_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_dst[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_gw[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_mask[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_flg[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_met[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ref[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_use[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ifc[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.monitoring.networkmon.monitoringIpv4RouteTable",
                          "ipv4RouteTable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "ipv4RouteTable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "destination") == 0) {
            if (++found_dst[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].destination)) return -1;
            strcpy(out->rows[r].destination, p->value);
        } else if (strcmp(p->parameter, "gateway") == 0) {
            if (++found_gw[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].gateway)) return -1;
            strcpy(out->rows[r].gateway, p->value);
        } else if (strcmp(p->parameter, "genmask") == 0) {
            if (++found_mask[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].genmask)) return -1;
            strcpy(out->rows[r].genmask, p->value);
        } else if (strcmp(p->parameter, "flags") == 0) {
            if (++found_flg[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].flags)) return -1;
            strcpy(out->rows[r].flags, p->value);
        } else if (strcmp(p->parameter, "metric") == 0) {
            if (++found_met[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].metric)) return -1;
            strcpy(out->rows[r].metric, p->value);
        } else if (strcmp(p->parameter, "ref") == 0) {
            if (++found_ref[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].ref)) return -1;
            strcpy(out->rows[r].ref, p->value);
        } else if (strcmp(p->parameter, "use") == 0) {
            if (++found_use[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].use)) return -1;
            strcpy(out->rows[r].use, p->value);
        } else if (strcmp(p->parameter, "iface") == 0) {
            if (++found_ifc[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].iface)) return -1;
            strcpy(out->rows[r].iface, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_dst[i] != 1U || found_gw[i] != 1U || found_mask[i] != 1U ||
            found_flg[i] != 1U || found_met[i] != 1U || found_ref[i] != 1U ||
            found_use[i] != 1U || found_ifc[i] != 1U) return -1;
    return 0;
}

int pm3000_xml_route6_table(const unsigned char *xml, size_t length,
                             struct pm3000_route6_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_dst[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_hop[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_flg[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_met[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ref[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_use[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ifc[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.monitoring.networkmon.monitoringIpv6RouteTable",
                          "ipv6RouteTable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "ipv6RouteTable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "destination") == 0) {
            if (++found_dst[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].destination)) return -1;
            strcpy(out->rows[r].destination, p->value);
        } else if (strcmp(p->parameter, "nextHop") == 0) {
            if (++found_hop[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].next_hop)) return -1;
            strcpy(out->rows[r].next_hop, p->value);
        } else if (strcmp(p->parameter, "flags") == 0) {
            if (++found_flg[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].flags)) return -1;
            strcpy(out->rows[r].flags, p->value);
        } else if (strcmp(p->parameter, "metric") == 0) {
            if (++found_met[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].metric)) return -1;
            strcpy(out->rows[r].metric, p->value);
        } else if (strcmp(p->parameter, "ref") == 0) {
            if (++found_ref[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].ref)) return -1;
            strcpy(out->rows[r].ref, p->value);
        } else if (strcmp(p->parameter, "use") == 0) {
            if (++found_use[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].use)) return -1;
            strcpy(out->rows[r].use, p->value);
        } else if (strcmp(p->parameter, "iface") == 0) {
            if (++found_ifc[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].iface)) return -1;
            strcpy(out->rows[r].iface, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_dst[i] != 1U || found_hop[i] != 1U || found_flg[i] != 1U ||
            found_met[i] != 1U || found_ref[i] != 1U || found_use[i] != 1U ||
            found_ifc[i] != 1U) return -1;
    return 0;
}

int pm3000_xml_serial_table(const unsigned char *xml, size_t length,
                              struct pm3000_serial_table *out) {
    struct document document;
    unsigned int i;
    unsigned int found_dev[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_prf[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_spd[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_sig[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_tx[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_rx[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_fe[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_pe[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_brk[PM3000_MAX_TABLE_ROWS] = {0};
    unsigned int found_ovr[PM3000_MAX_TABLE_ROWS] = {0};
    if (table_parse_start(xml, length,
                          "units.monitoring.serialstatistics",
                          "serialstatistictable", &document) != 0) return -1;
    out->row_count = document.table_row_count;
    memset(out->rows, 0, sizeof(out->rows));
    for (i = 0U; i < document.row_param_count; ++i) {
        const struct xml_row_param *p = &document.row_params[i];
        unsigned int r = p->row;
        if (!valid_row_parameter(p)) return -1;
        if (strcmp(p->table_id, "serialstatistictable") != 0 || r >= out->row_count) continue;
        if (strcmp(p->parameter, "devicename") == 0) {
            if (++found_dev[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].device_name)) return -1;
            strcpy(out->rows[r].device_name, p->value);
        } else if (strcmp(p->parameter, "portprofile") == 0) {
            if (++found_prf[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].port_profile)) return -1;
            strcpy(out->rows[r].port_profile, p->value);
        } else if (strcmp(p->parameter, "speed") == 0) {
            if (++found_spd[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].speed)) return -1;
            strcpy(out->rows[r].speed, p->value);
        } else if (strcmp(p->parameter, "signals") == 0) {
            if (++found_sig[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].signals)) return -1;
            strcpy(out->rows[r].signals, p->value);
        } else if (strcmp(p->parameter, "txBytes") == 0) {
            if (++found_tx[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].tx_bytes)) return -1;
            strcpy(out->rows[r].tx_bytes, p->value);
        } else if (strcmp(p->parameter, "rxBytes") == 0) {
            if (++found_rx[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].rx_bytes)) return -1;
            strcpy(out->rows[r].rx_bytes, p->value);
        } else if (strcmp(p->parameter, "frameError") == 0) {
            if (++found_fe[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].frame_error)) return -1;
            strcpy(out->rows[r].frame_error, p->value);
        } else if (strcmp(p->parameter, "parityError") == 0) {
            if (++found_pe[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].parity_error)) return -1;
            strcpy(out->rows[r].parity_error, p->value);
        } else if (strcmp(p->parameter, "break") == 0) {
            if (++found_brk[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].brk)) return -1;
            strcpy(out->rows[r].brk, p->value);
        } else if (strcmp(p->parameter, "overrun") == 0) {
            if (++found_ovr[r] != 1U || strlen(p->value) >= sizeof(out->rows[r].overrun)) return -1;
            strcpy(out->rows[r].overrun, p->value);
        }
    }
    for (i = 0U; i < out->row_count; ++i)
        if (found_dev[i] != 1U || found_prf[i] != 1U || found_spd[i] != 1U ||
            found_sig[i] != 1U || found_tx[i] != 1U || found_rx[i] != 1U ||
            found_fe[i] != 1U || found_pe[i] != 1U || found_brk[i] != 1U ||
            found_ovr[i] != 1U) return -1;
    return 0;
}
