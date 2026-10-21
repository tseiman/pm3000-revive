#include "controller_xml.h"

#include <ctype.h>
#include <stdint.h>
#include <string.h>

#define XML_MAX_BYTES (1024U * 1024U)
#define XML_MAX_DEPTH 32U
#define XML_MAX_NAME 63U
#define XML_MAX_TEXT 255U
#define XML_MAX_ATTRS 32U
#define XML_MAX_PATHS 64U
#define XML_MAX_PARAMETERS 128U

struct frame {
    char name[XML_MAX_NAME + 1U];
    char id[XML_MAX_TEXT + 1U];
    char structure[XML_MAX_NAME + 1U];
    char text[XML_MAX_TEXT + 1U];
    size_t text_length;
};

struct parameter_value {
    char form[XML_MAX_TEXT + 1U];
    char parameter[XML_MAX_TEXT + 1U];
    char structure[XML_MAX_NAME + 1U];
    char container_name[XML_MAX_NAME + 1U];
    char container_id[XML_MAX_TEXT + 1U];
    char container_structure[XML_MAX_NAME + 1U];
    unsigned int direct_form_child;
    char value[XML_MAX_TEXT + 1U];
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
};

static int valid_utf8(const unsigned char *input, size_t length) {
    size_t offset = 0U;
    while (offset < length) {
        unsigned char first = input[offset++];
        uint32_t value;
        size_t remaining;
        if (first < 0x80U) { if (first == 0U) return 0; continue; }
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
            value < (first <= 0xdfU ? 0x80U : first <= 0xefU ? 0x800U : 0x10000U)) return 0;
    }
    return 1;
}

static void skip_space(struct document *document) {
    while (document->offset < document->length &&
           isspace((unsigned char)document->input[document->offset]))
        ++document->offset;
}

static int parse_name(struct document *document, char *output, size_t capacity) {
    size_t start = document->offset;
    size_t amount;
    while (document->offset < document->length) {
        unsigned char value = document->input[document->offset];
        if (!(isalnum(value) || value == '_' || value == '-' || value == ':')) break;
        ++document->offset;
    }
    amount = document->offset - start;
    if (amount == 0U || amount >= capacity) return -1;
    memcpy(output, document->input + start, amount);
    output[amount] = '\0';
    return 0;
}

static int append_byte(char *output, size_t *length, size_t capacity,
                       unsigned char value) {
    if (value == 0U || value < 0x20U || *length + 1U >= capacity) return -1;
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
                record->direct_form_child =
                    strcmp(container->name, "section") == 0 &&
                    strcmp(container->id, form) == 0 &&
                    strcmp(container->structure, "form") == 0;
            }
            strcpy(record->value, frame->text);
        }
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
    --document->depth;
    return 0;
}

static int start_element(struct document *document, int *self_closing) {
    struct frame *frame;
    char attribute_names[XML_MAX_ATTRS][XML_MAX_NAME + 1U];
    char id[XML_MAX_TEXT + 1U] = {0};
    char path[XML_MAX_TEXT + 1U] = {0};
    char structure[XML_MAX_NAME + 1U] = {0};
    unsigned int attribute_count = 0U;
    if (document->depth >= XML_MAX_DEPTH) return -1;
    frame = &document->stack[document->depth];
    memset(frame, 0, sizeof(*frame));
    if (parse_name(document, frame->name, sizeof(frame->name)) != 0) return -1;
    while (1) {
        char name[XML_MAX_NAME + 1U];
        char value[XML_MAX_TEXT + 1U];
        unsigned int index;
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
        if (attribute_count >= XML_MAX_ATTRS ||
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
        else if (strcmp(name, "structure") == 0) {
            if (strlen(value) > XML_MAX_NAME) return -1;
            strcpy(structure, value);
        }
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
    }
    if (strcmp(frame->name, "control") == 0 && has_ancestor(document, "controls") &&
        has_ancestor(document, "payload")) {
        if (strcmp(id, "targPowerOn") == 0) {
            document->power_on = 1U;
        } else if (strcmp(id, "targPowerOff") == 0) {
            document->power_off = 1U;
        } else if (strcmp(id, "targCycle") == 0) {
            document->power_cycle = 1U;
        }
    }
    ++document->depth;
    if (*self_closing && close_element(document, frame->name) != 0) return -1;
    return 0;
}

static int parse_document(const unsigned char *xml, size_t length,
                          struct document *document) {
    memset(document, 0, sizeof(*document));
    if (xml == NULL || length == 0U || length > XML_MAX_BYTES ||
        !valid_utf8(xml, length)) return -1;
    document->input = xml;
    document->length = length;
    while (document->offset < document->length) {
        if (document->input[document->offset] != '<') {
            size_t start = document->offset;
            while (document->offset < document->length &&
                   document->input[document->offset] != '<') ++document->offset;
            if (document->depth == 0U) {
                size_t index;
                for (index = start; index < document->offset; ++index)
                    if (!isspace((unsigned char)document->input[index])) return -1;
            } else {
                struct frame *frame = &document->stack[document->depth - 1U];
                if ((document->depth == 2U &&
                     (strcmp(frame->name, "action") == 0 ||
                      strcmp(frame->name, "sid") == 0)) ||
                    (document->depth == 3U && strcmp(frame->name, "path") == 0 &&
                     ancestor_is(document, 2U, "paths")) ||
                    (strcmp(frame->name, "value") == 0 &&
                     ancestor_form_id(document) != NULL)) {
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
            size_t end;
            if (document->offset != 1U) return -1;
            end = document->offset + 1U;
            while (end + 1U < document->length &&
                   !(document->input[end] == '?' && document->input[end + 1U] == '>')) ++end;
            if (end + 1U >= document->length) return -1;
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
                          int *can_manage) {
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
