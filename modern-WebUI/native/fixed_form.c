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
    uint32_t choice_field_mask;
};

static const struct pm3000_xml_fixed_field help_fields[] = {
    {"applanguage", "combo", NULL, NULL},
    {"url", "RWtext", NULL, NULL}
};
static const struct pm3000_xml_fixed_parameter help_parameters[] = {
    {"applanguage", "combo", NULL, NULL},
    {"url", "RWtext", NULL, NULL}
};
static const char *const help_keys[] = {"applianceLanguage", "url"};
static const unsigned char help_types[] = {0U, 0U};

static const struct pm3000_xml_fixed_field buffering_fields[] = {
    {"local_size", "RWtext", "local", NULL},
    {"local_segments", "RWtext", "local", NULL},
    {"nfs_server", "RWtext", "nfs", NULL},
    {"nfs_path", "RWtext", "nfs", NULL},
    {"nfs_size", "RWtext", "nfs", NULL},
    {"nfs_segments", "RWtext", "nfs", NULL},
    {"syslog_facility", "combo", "syslog", NULL}
};
static const struct pm3000_xml_fixed_parameter buffering_parameters[] = {
    {"local", "title", NULL, NULL},
    {"local_size", "RWtext", "local", NULL},
    {"local_segments", "RWtext", "local", NULL},
    {"nfs", "title", NULL, NULL},
    {"nfs_notice", "notice", "nfs", NULL},
    {"nfs_server", "RWtext", "nfs", NULL},
    {"nfs_path", "RWtext", "nfs", NULL},
    {"nfs_size", "RWtext", "nfs", NULL},
    {"nfs_segments", "RWtext", "nfs", NULL},
    {"syslog", "title", NULL, NULL},
    {"syslog_facility", "combo", "syslog", NULL}
};
static const char *const buffering_keys[] = {
    "localSize", "localSegments", "nfsServer", "nfsPath", "nfsSize",
    "nfsSegments", "syslogFacility"
};
static const unsigned char buffering_types[] = {1U, 1U, 0U, 0U, 1U, 1U, 0U};

static const struct pm3000_xml_fixed_field logging_fields[] = {
    {"sessionlogenable", "checkbox", "sessiontitle", "title"},
    {"destination", "combo", "sessionlogenable", "checkbox"},
    {"enabletimestamp", "combo", "sessionlogenable", "checkbox"},
    {"alertenable", "checkbox", "sessionlogenable", "checkbox"},
    {"alertstring1", "RWtext", "alertenable", "checkbox"},
    {"alertstring2", "RWtext", "alertenable", "checkbox"},
    {"alertstring3", "RWtext", "alertenable", "checkbox"},
    {"alertstring4", "RWtext", "alertenable", "checkbox"},
    {"alertstring5", "RWtext", "alertenable", "checkbox"},
    {"alertstring6", "RWtext", "alertenable", "checkbox"},
    {"alertstring7", "RWtext", "alertenable", "checkbox"},
    {"alertstring8", "RWtext", "alertenable", "checkbox"},
    {"alertstring9", "RWtext", "alertenable", "checkbox"},
    {"alertstring10", "RWtext", "alertenable", "checkbox"}
};
static const struct pm3000_xml_fixed_parameter logging_parameters[] = {
    {"sessiontitle", "title", NULL, NULL},
    {"sessionlogenable", "checkbox", "sessiontitle", "title"},
    {"notice", "notice", "sessionlogenable", "checkbox"},
    {"destination", "combo", "sessionlogenable", "checkbox"},
    {"enabletimestamp", "combo", "sessionlogenable", "checkbox"},
    {"alertenable", "checkbox", "sessionlogenable", "checkbox"},
    {"alertstring1", "RWtext", "alertenable", "checkbox"},
    {"alertstring2", "RWtext", "alertenable", "checkbox"},
    {"alertstring3", "RWtext", "alertenable", "checkbox"},
    {"alertstring4", "RWtext", "alertenable", "checkbox"},
    {"alertstring5", "RWtext", "alertenable", "checkbox"},
    {"alertstring6", "RWtext", "alertenable", "checkbox"},
    {"alertstring7", "RWtext", "alertenable", "checkbox"},
    {"alertstring8", "RWtext", "alertenable", "checkbox"},
    {"alertstring9", "RWtext", "alertenable", "checkbox"},
    {"alertstring10", "RWtext", "alertenable", "checkbox"}
};

static const struct pm3000_xml_fixed_field time_zone_fields[] = {
    {"customtimezone", "radiobox", NULL, NULL},
    {"timezone_list", "combo", "@no", "radio"},
    {"tzName", "RWtext", "@yes", "radio"},
    {"stdTimeAcronym", "RWtext", "@yes", "radio"},
    {"gmtOffset", "RWtext", "@yes", "radio"},
    {"enableDst", "checkbox", "@yes", "radio"},
    {"dstAcronym", "RWtext", "enableDst", "checkbox"},
    {"saveTime", "RWtext", "enableDst", "checkbox"},
    {"startMonth", "combo", "enableDst", "checkbox"},
    {"startWeek", "combo", "enableDst", "checkbox"},
    {"startWeekday", "combo", "enableDst", "checkbox"},
    {"startHour", "RWtext", "enableDst", "checkbox"},
    {"endMonth", "combo", "enableDst", "checkbox"},
    {"endWeek", "combo", "enableDst", "checkbox"},
    {"endWeekday", "combo", "enableDst", "checkbox"},
    {"endHour", "RWtext", "enableDst", "checkbox"}
};
static const struct pm3000_xml_fixed_parameter time_zone_parameters[] = {
    {"customtimezone", "radiobox", NULL, NULL},
    {"@no", "radio", "customtimezone", "radiobox"},
    {"timezone_list", "combo", "@no", "radio"},
    {"@yes", "radio", "customtimezone", "radiobox"},
    {"tzName", "RWtext", "@yes", "radio"},
    {"stdTimeAcronym", "RWtext", "@yes", "radio"},
    {"gmtOffset", "RWtext", "@yes", "radio"},
    {"enableDst", "checkbox", "@yes", "radio"},
    {"dstAcronym", "RWtext", "enableDst", "checkbox"},
    {"saveTime", "RWtext", "enableDst", "checkbox"},
    {"startMonth", "combo", "enableDst", "checkbox"},
    {"startWeek", "combo", "enableDst", "checkbox"},
    {"startWeekday", "combo", "enableDst", "checkbox"},
    {"startHour", "RWtext", "enableDst", "checkbox"},
    {"endMonth", "combo", "enableDst", "checkbox"},
    {"endWeek", "combo", "enableDst", "checkbox"},
    {"endWeekday", "combo", "enableDst", "checkbox"},
    {"endHour", "RWtext", "enableDst", "checkbox"}
};

static const struct fixed_descriptor help_descriptor = {
    "units.applianceSettings.help", "sessionform", help_fields, help_parameters,
    help_keys, help_types, 2U, 2U, UINT32_C(1) << 0
};
static const struct fixed_descriptor buffering_descriptor = {
    "units.event_notification.global_settings_databuffering",
    "global_settings_form", buffering_fields, buffering_parameters,
    buffering_keys, buffering_types, 7U, 11U, UINT32_C(1) << 6
};
static const struct fixed_descriptor logging_descriptor = {
    "units.event_notification.sessions", "sessionform", logging_fields,
    logging_parameters, NULL, NULL, 14U, 16U,
    (UINT32_C(1) << 1) | (UINT32_C(1) << 2)
};
static const struct fixed_descriptor time_zone_descriptor = {
    "units.applianceSettings.date_and_time.time_zone", "time_zoneform",
    time_zone_fields, time_zone_parameters, NULL, NULL, 16U, 18U,
    (UINT32_C(1) << 1) | (UINT32_C(1) << 8) | (UINT32_C(1) << 9) |
    (UINT32_C(1) << 10) | (UINT32_C(1) << 12) | (UINT32_C(1) << 13) |
    (UINT32_C(1) << 14)
};

static const struct fixed_descriptor *descriptor(pm3000_fixed_form_kind kind) {
    if (kind == PM3000_FORM_HELP_LANGUAGE) return &help_descriptor;
    if (kind == PM3000_FORM_DATA_BUFFERING) return &buffering_descriptor;
    if (kind == PM3000_FORM_APPLIANCE_LOGGING) return &logging_descriptor;
    if (kind == PM3000_FORM_TIME_ZONE) return &time_zone_descriptor;
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

static int boolean_text(const char *value) {
    return strcmp(value, "true") == 0 || strcmp(value, "false") == 0;
}

static int destination(const char *value) {
    return strcmp(value, "local") == 0 || strcmp(value, "nfs") == 0 ||
           strcmp(value, "syslog") == 0 || strcmp(value, "dsview") == 0;
}

static int ascii_identifier(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (!(isalpha(*cursor) || *cursor == '_')) return 0;
    while (*++cursor != '\0') if (!(isalnum(*cursor) || *cursor == '_')) return 0;
    return 1;
}

static int acronym(const char *value) {
    size_t index, length = strlen(value);
    if (length < 1U || length > 4U) return 0;
    for (index = 0U; index < length; ++index)
        if (!isalpha((unsigned char)value[index])) return 0;
    return 1;
}

static int hour_minute(const char *value, unsigned int minimum_hour,
                       unsigned int maximum_hour, int final_hour_zero_only) {
    const char *colon = strchr(value, ':');
    unsigned long hour, minute;
    char hour_text[4];
    size_t amount;
    if (colon == NULL || strchr(colon + 1, ':') != NULL || strlen(colon + 1) != 2U ||
        !isdigit((unsigned char)colon[1]) || !isdigit((unsigned char)colon[2])) return 0;
    amount = (size_t)(colon - value);
    if (amount == 0U || amount >= sizeof(hour_text)) return 0;
    memcpy(hour_text, value, amount); hour_text[amount] = '\0';
    minute = (unsigned long)(colon[1] - '0') * 10U + (unsigned long)(colon[2] - '0');
    if (decimal_value(hour_text, minimum_hour, maximum_hour, &hour) != 0 ||
        minute > 59U) return 0;
    return !(final_hour_zero_only && hour == maximum_hour && minute != 0U);
}

static int gmt_offset(const char *value) {
    return hour_minute(value[0] == '-' ? value + 1 : value, 1U, 14U, 0);
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
    if (kind == PM3000_FORM_DATA_BUFFERING) {
        if (decimal_value(values[0], 0U, 2048U, &ignored) != 0 ||
            decimal_value(values[1], 1U, 9U, &ignored) != 0 ||
            strlen(values[2]) > 100U || !server_name(values[2]) ||
            strlen(values[3]) > 100U ||
            decimal_value(values[4], 0U, 99999U, &ignored) != 0 ||
            decimal_value(values[5], 0U, 99U, &ignored) != 0 || !facility(values[6])) return -1;
        return 0;
    }
    if (kind == PM3000_FORM_TIME_ZONE) {
        if ((strcmp(values[0], "no") != 0 && strcmp(values[0], "yes") != 0) ||
            values[1][0] == '\0' || strlen(values[1]) > 32U ||
            !ascii_identifier(values[2]) || !acronym(values[3]) ||
            !gmt_offset(values[4]) || !boolean_text(values[5]) ||
            !acronym(values[6]) || !hour_minute(values[7], 0U, 5U, 1)) return -1;
        if (decimal_value(values[8], 1U, 12U, &ignored) != 0 ||
            decimal_value(values[9], 1U, 5U, &ignored) != 0 ||
            decimal_value(values[10], 1U, 7U, &ignored) != 0 ||
            !hour_minute(values[11], 1U, 12U, 0) ||
            decimal_value(values[12], 1U, 12U, &ignored) != 0 ||
            decimal_value(values[13], 1U, 5U, &ignored) != 0 ||
            decimal_value(values[14], 1U, 7U, &ignored) != 0 ||
            !hour_minute(values[15], 1U, 12U, 0)) return -1;
        if (strcmp(values[5], "true") == 0 && strcmp(values[8], values[12]) == 0 &&
            strcmp(values[10], values[14]) == 0 && strcmp(values[11], values[15]) == 0)
            return -1;
        return 0;
    }
    if (kind != PM3000_FORM_APPLIANCE_LOGGING || !boolean_text(values[0]) ||
        !destination(values[1]) ||
        (strcmp(values[2], "yes") != 0 && strcmp(values[2], "no") != 0) ||
        !boolean_text(values[3])) return -1;
    for (index = 4U; index < 14U; ++index)
        if (strlen(values[index]) > 64U) return -1;
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
    for (index = 0U; index < snapshot->form.choice_count; ++index) {
        sha256_update(&context, &snapshot->form.choice_fields[index], 1U);
        sha256_update(&context, snapshot->form.choices[index],
                      strlen(snapshot->form.choices[index]) + 1U);
    }
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

static int choices_equal(const struct pm3000_fixed_snapshot *snapshot,
                         unsigned int field, const char *const *expected,
                         unsigned int expected_count) {
    unsigned int index, found = 0U;
    for (index = 0U; index < snapshot->form.choice_count; ++index) {
        if (snapshot->form.choice_fields[index] != field) continue;
        if (found >= expected_count || strcmp(snapshot->form.choices[index], expected[found]) != 0)
            return 0;
        ++found;
    }
    return found == expected_count;
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
                              value->choice_field_mask, &out->form) != 0 ||
        validate_values(kind, out->form.values) != 0) return -1;
    if (kind == PM3000_FORM_HELP_LANGUAGE) {
        if (!pm3000_fixed_language_allowed(out, out->form.values[0])) return -1;
        for (index = 0U; index < out->form.choice_count; ++index)
            if (out->form.choice_fields[index] != 0U ||
                !valid_xml_text(out->form.choices[index])) return -1;
    } else if (kind == PM3000_FORM_DATA_BUFFERING) {
        static const char *const facilities[] = {
            "LOG_LOCAL0", "LOG_LOCAL1", "LOG_LOCAL2",
            "LOG_LOCAL3", "LOG_LOCAL4", "LOG_LOCAL5"
        };
        if (!choices_equal(out, 6U, facilities, 6U)) return -1;
    } else if (kind == PM3000_FORM_TIME_ZONE) {
        static const char *const months[] = {"1", "2", "3", "4", "5", "6", "7", "8", "9", "10", "11", "12"};
        static const char *const weeks[] = {"1", "2", "3", "4", "5"};
        static const char *const weekdays[] = {"1", "2", "3", "4", "5", "6", "7"};
        unsigned int zone_count = 0U, selected = 0U;
        for (index = 0U; index < out->form.choice_count; ++index) {
            if (out->form.choice_fields[index] == 1U) {
                ++zone_count;
                if (strcmp(out->form.choices[index], out->form.values[1]) == 0) ++selected;
            }
        }
        if (zone_count == 0U || selected != 1U ||
            !choices_equal(out, 8U, months, 12U) || !choices_equal(out, 12U, months, 12U) ||
            !choices_equal(out, 9U, weeks, 5U) || !choices_equal(out, 13U, weeks, 5U) ||
            !choices_equal(out, 10U, weekdays, 7U) || !choices_equal(out, 14U, weekdays, 7U) ||
            out->form.choice_count != zone_count + 48U) return -1;
    } else {
        static const char *const destinations[] = {"local", "nfs", "syslog", "dsview"};
        static const char *const timestamps[] = {"yes", "no"};
        if (!choices_equal(out, 1U, destinations, 4U) ||
            !choices_equal(out, 2U, timestamps, 2U) ||
            out->form.choice_count != 6U) return -1;
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

static int json_boolean(struct json_cursor *cursor, char output[PM3000_FIXED_VALUE_SIZE]) {
    json_space(cursor);
    if (cursor->offset + 4U <= cursor->length &&
        memcmp(cursor->data + cursor->offset, "true", 4U) == 0) {
        strcpy(output, "true"); cursor->offset += 4U; return 0;
    }
    if (cursor->offset + 5U <= cursor->length &&
        memcmp(cursor->data + cursor->offset, "false", 5U) == 0) {
        strcpy(output, "false"); cursor->offset += 5U; return 0;
    }
    return -1;
}

static int json_alert_strings(struct json_cursor *cursor,
                              struct pm3000_fixed_input *out) {
    unsigned int index;
    if (json_char(cursor, '[') != 0) return -1;
    for (index = 0U; index < 10U; ++index) {
        if (index > 0U && json_char(cursor, ',') != 0) return -1;
        json_space(cursor);
        if (json_string(cursor, out->values[4U + index],
                        sizeof(out->values[4U + index])) != 0 ||
            strlen(out->values[4U + index]) > 64U ||
            !valid_xml_text(out->values[4U + index])) return -1;
        out->present[4U + index] = 1U;
    }
    return json_char(cursor, ']');
}

static int parse_logging_request(const unsigned char *json, size_t length,
                                 struct pm3000_fixed_input *out) {
    struct json_cursor cursor = {json, length, 0U};
    unsigned int seen = 0U, members = 0U;
    if (length == 0U || !valid_utf8(json, length) || json_char(&cursor, '{') != 0)
        return -1;
    memset(out, 0, sizeof(*out));
    for (;;) {
        char key[64]; unsigned int bit;
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset; break;
        }
        if (members++ > 0U && json_char(&cursor, ',') != 0) return -1;
        json_space(&cursor);
        if (json_string(&cursor, key, sizeof(key)) != 0 || json_char(&cursor, ':') != 0)
            return -1;
        if (strcmp(key, "sessionLoggingEnabled") == 0) bit = 0U;
        else if (strcmp(key, "destination") == 0) bit = 1U;
        else if (strcmp(key, "timestampEnabled") == 0) bit = 2U;
        else if (strcmp(key, "alertsEnabled") == 0) bit = 3U;
        else if (strcmp(key, "alertStrings") == 0) bit = 4U;
        else return -1;
        if ((seen & (1U << bit)) != 0U) return -1;
        seen |= 1U << bit;
        json_space(&cursor);
        if (bit == 0U || bit == 3U) {
            unsigned int field = bit == 0U ? 0U : 3U;
            if (json_boolean(&cursor, out->values[field]) != 0) return -1;
            out->present[field] = 1U;
        } else if (bit == 1U) {
            if (json_string(&cursor, out->values[1], sizeof(out->values[1])) != 0 ||
                !destination(out->values[1])) return -1;
            out->present[1] = 1U;
        } else if (bit == 2U) {
            char boolean[PM3000_FIXED_VALUE_SIZE];
            if (json_boolean(&cursor, boolean) != 0) return -1;
            strcpy(out->values[2], strcmp(boolean, "true") == 0 ? "yes" : "no");
            out->present[2] = 1U;
        } else if (json_alert_strings(&cursor, out) != 0) return -1;
    }
    json_space(&cursor);
    if (cursor.offset != cursor.length || (seen & 1U) == 0U) return -1;
    if (strcmp(out->values[0], "false") == 0) return seen == 1U ? 0 : -1;
    if ((seen & 15U) != 15U) return -1;
    if (strcmp(out->values[3], "false") == 0) return seen == 15U ? 0 : -1;
    return seen == 31U ? 0 : -1;
}

static int parse_time_zone_transition(struct json_cursor *cursor,
                                      struct pm3000_fixed_input *out,
                                      unsigned int base) {
    unsigned int seen = 0U, members = 0U;
    if (json_char(cursor, '{') != 0) return -1;
    for (;;) {
        char key[24]; unsigned int relative;
        json_space(cursor);
        if (cursor->offset < cursor->length && cursor->data[cursor->offset] == '}') {
            ++cursor->offset; break;
        }
        if (members++ > 0U && json_char(cursor, ',') != 0) return -1;
        json_space(cursor);
        if (json_string(cursor, key, sizeof(key)) != 0 || json_char(cursor, ':') != 0) return -1;
        json_space(cursor);
        if (strcmp(key, "month") == 0) relative = 0U;
        else if (strcmp(key, "week") == 0) relative = 1U;
        else if (strcmp(key, "weekday") == 0) relative = 2U;
        else if (strcmp(key, "hour") == 0) relative = 3U;
        else return -1;
        if ((seen & (1U << relative)) != 0U ||
            json_string(cursor, out->values[base + relative],
                        sizeof(out->values[base + relative])) != 0) return -1;
        seen |= 1U << relative; out->present[base + relative] = 1U;
    }
    return seen == 15U ? 0 : -1;
}

static int parse_time_zone_dst(struct json_cursor *cursor,
                               struct pm3000_fixed_input *out) {
    unsigned int seen = 0U, members = 0U;
    if (json_char(cursor, '{') != 0) return -1;
    for (;;) {
        char key[24]; unsigned int bit;
        json_space(cursor);
        if (cursor->offset < cursor->length && cursor->data[cursor->offset] == '}') {
            ++cursor->offset; break;
        }
        if (members++ > 0U && json_char(cursor, ',') != 0) return -1;
        json_space(cursor);
        if (json_string(cursor, key, sizeof(key)) != 0 || json_char(cursor, ':') != 0) return -1;
        json_space(cursor);
        if (strcmp(key, "enabled") == 0) bit = 0U;
        else if (strcmp(key, "acronym") == 0) bit = 1U;
        else if (strcmp(key, "saveTime") == 0) bit = 2U;
        else if (strcmp(key, "start") == 0) bit = 3U;
        else if (strcmp(key, "end") == 0) bit = 4U;
        else return -1;
        if ((seen & (1U << bit)) != 0U) return -1;
        seen |= 1U << bit;
        if (bit == 0U) {
            if (json_boolean(cursor, out->values[5]) != 0) return -1;
            out->present[5] = 1U;
        } else if (bit == 1U) {
            if (json_string(cursor, out->values[6], sizeof(out->values[6])) != 0) return -1;
            out->present[6] = 1U;
        } else if (bit == 2U) {
            if (json_string(cursor, out->values[7], sizeof(out->values[7])) != 0) return -1;
            out->present[7] = 1U;
        } else if (bit == 3U) {
            if (parse_time_zone_transition(cursor, out, 8U) != 0) return -1;
        } else if (parse_time_zone_transition(cursor, out, 12U) != 0) return -1;
    }
    if ((seen & 1U) == 0U) return -1;
    return strcmp(out->values[5], "true") == 0 ? (seen == 31U ? 0 : -1) :
                                                   (seen == 1U ? 0 : -1);
}

static int parse_time_zone_custom(struct json_cursor *cursor,
                                  struct pm3000_fixed_input *out) {
    unsigned int seen = 0U, members = 0U;
    if (json_char(cursor, '{') != 0) return -1;
    for (;;) {
        char key[32]; unsigned int bit;
        json_space(cursor);
        if (cursor->offset < cursor->length && cursor->data[cursor->offset] == '}') {
            ++cursor->offset; break;
        }
        if (members++ > 0U && json_char(cursor, ',') != 0) return -1;
        json_space(cursor);
        if (json_string(cursor, key, sizeof(key)) != 0 || json_char(cursor, ':') != 0) return -1;
        json_space(cursor);
        if (strcmp(key, "name") == 0) bit = 0U;
        else if (strcmp(key, "standardAcronym") == 0) bit = 1U;
        else if (strcmp(key, "gmtOffset") == 0) bit = 2U;
        else if (strcmp(key, "dst") == 0) bit = 3U;
        else return -1;
        if ((seen & (1U << bit)) != 0U) return -1;
        seen |= 1U << bit;
        if (bit < 3U) {
            if (json_string(cursor, out->values[2U + bit],
                            sizeof(out->values[2U + bit])) != 0) return -1;
            out->present[2U + bit] = 1U;
        } else if (parse_time_zone_dst(cursor, out) != 0) return -1;
    }
    return seen == 15U ? 0 : -1;
}

static int parse_time_zone_request(const unsigned char *json, size_t length,
                                   struct pm3000_fixed_input *out) {
    struct json_cursor cursor = {json, length, 0U};
    unsigned int seen = 0U, members = 0U;
    char mode[16] = {0};
    if (length == 0U || !valid_utf8(json, length) || json_char(&cursor, '{') != 0) return -1;
    memset(out, 0, sizeof(*out));
    for (;;) {
        char key[32]; unsigned int bit;
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset; break;
        }
        if (members++ > 0U && json_char(&cursor, ',') != 0) return -1;
        json_space(&cursor);
        if (json_string(&cursor, key, sizeof(key)) != 0 || json_char(&cursor, ':') != 0) return -1;
        json_space(&cursor);
        if (strcmp(key, "mode") == 0) bit = 0U;
        else if (strcmp(key, "predefinedZone") == 0) bit = 1U;
        else if (strcmp(key, "custom") == 0) bit = 2U;
        else return -1;
        if ((seen & (1U << bit)) != 0U) return -1;
        seen |= 1U << bit;
        if (bit == 0U) {
            if (json_string(&cursor, mode, sizeof(mode)) != 0) return -1;
        } else if (bit == 1U) {
            if (json_string(&cursor, out->values[1], sizeof(out->values[1])) != 0) return -1;
            out->present[1] = 1U;
        } else if (parse_time_zone_custom(&cursor, out) != 0) return -1;
    }
    json_space(&cursor);
    if (cursor.offset != cursor.length || (seen & 1U) == 0U) return -1;
    out->present[0] = 1U;
    if (strcmp(mode, "predefined") == 0 && seen == 3U) {
        strcpy(out->values[0], "no"); return 0;
    }
    if (strcmp(mode, "custom") == 0 && seen == 5U) {
        strcpy(out->values[0], "yes"); return 0;
    }
    return -1;
}

int pm3000_fixed_parse_request(pm3000_fixed_form_kind kind,
                               const unsigned char *json, size_t length,
                               struct pm3000_fixed_input *out) {
    const struct fixed_descriptor *value = descriptor(kind);
    struct json_cursor cursor = {json, length, 0U};
    unsigned int seen[PM3000_FIXED_MAX_FIELDS] = {0}, members = 0U;
    if (value == NULL || out == NULL || json == NULL || length == 0U) return -1;
    if (kind == PM3000_FORM_APPLIANCE_LOGGING)
        return parse_logging_request(json, length, out);
    if (kind == PM3000_FORM_TIME_ZONE)
        return parse_time_zone_request(json, length, out);
    if (!valid_utf8(json, length) || json_char(&cursor, '{') != 0) return -1;
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
        out->present[index] = 1U;
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
        if (snapshot->form.choice_fields[index] == 0U &&
            strcmp(snapshot->form.choices[index], language) == 0) return 1;
    return 0;
}

int pm3000_fixed_merge_inactive(pm3000_fixed_form_kind kind,
                                const struct pm3000_fixed_snapshot *snapshot,
                                struct pm3000_fixed_input *input) {
    unsigned int index, count = pm3000_fixed_field_count(kind);
    if (snapshot == NULL || input == NULL || count == 0U) return -1;
    for (index = 0U; index < count; ++index) {
        if (input->present[index] == 0U) {
            if (strlen(snapshot->form.values[index]) >= sizeof(input->values[index])) return -1;
            strcpy(input->values[index], snapshot->form.values[index]);
        }
    }
    if (validate_values(kind, input->values) != 0) return -1;
    if (kind == PM3000_FORM_TIME_ZONE) {
        unsigned int matches = 0U;
        for (index = 0U; index < snapshot->form.choice_count; ++index)
            if (snapshot->form.choice_fields[index] == 1U &&
                strcmp(snapshot->form.choices[index], input->values[1]) == 0) ++matches;
        if (matches != 1U) return -1;
    }
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
    if (kind == PM3000_FORM_TIME_ZONE) {
        amount = snprintf(output + used, capacity - used,
                          "<parameter id=\"customtimezone\" structure=\"radiobox\"><value>%s</value>",
                          escaped[0]);
        if (amount < 0 || (size_t)amount >= capacity - used) return -1;
        used += (size_t)amount;
        if (strcmp(input->values[0], "no") == 0) {
            amount = snprintf(output + used, capacity - used,
                              "<parameter id=\"timezone_list\" structure=\"combo\"><value>%s</value></parameter>",
                              escaped[1]);
        } else {
            amount = snprintf(output + used, capacity - used,
                              "<parameter id=\"tzName\" structure=\"RWtext\"><value>%s</value></parameter>"
                              "<parameter id=\"stdTimeAcronym\" structure=\"RWtext\"><value>%s</value></parameter>"
                              "<parameter id=\"gmtOffset\" structure=\"RWtext\"><value>%s</value></parameter>"
                              "<parameter id=\"enableDst\" structure=\"checkbox\"><value>%s</value>",
                              escaped[2], escaped[3], escaped[4], escaped[5]);
        }
        if (amount < 0 || (size_t)amount >= capacity - used) return -1;
        used += (size_t)amount;
        if (strcmp(input->values[0], "yes") == 0) {
            if (strcmp(input->values[5], "true") == 0) {
                for (index = 6U; index < 16U; ++index) {
                    amount = snprintf(output + used, capacity - used,
                                      "<parameter id=\"%s\" structure=\"%s\"><value>%s</value></parameter>",
                                      value->fields[index].id, value->fields[index].structure,
                                      escaped[index]);
                    if (amount < 0 || (size_t)amount >= capacity - used) return -1;
                    used += (size_t)amount;
                }
            }
            amount = snprintf(output + used, capacity - used, "</parameter>");
            if (amount < 0 || (size_t)amount >= capacity - used) return -1;
            used += (size_t)amount;
        }
        amount = snprintf(output + used, capacity - used, "</parameter></section>");
        return amount < 0 || (size_t)amount >= capacity - used ? -1 : 0;
    }
    if (kind == PM3000_FORM_APPLIANCE_LOGGING) {
        amount = snprintf(output + used, capacity - used,
                          "<parameter id=\"sessionlogenable\" structure=\"checkbox\"><value>%s</value>",
                          escaped[0]);
        if (amount < 0 || (size_t)amount >= capacity - used) return -1;
        used += (size_t)amount;
        if (strcmp(input->values[0], "true") == 0) {
            amount = snprintf(output + used, capacity - used,
                              "<parameter id=\"destination\" structure=\"combo\"><value>%s</value></parameter>"
                              "<parameter id=\"enabletimestamp\" structure=\"combo\"><value>%s</value></parameter>"
                              "<parameter id=\"alertenable\" structure=\"checkbox\"><value>%s</value>",
                              escaped[1], escaped[2], escaped[3]);
            if (amount < 0 || (size_t)amount >= capacity - used) return -1;
            used += (size_t)amount;
            if (strcmp(input->values[3], "true") == 0) {
                for (index = 4U; index < 14U; ++index) {
                    amount = snprintf(output + used, capacity - used,
                                      "<parameter id=\"%s\" structure=\"RWtext\"><value>%s</value></parameter>",
                                      value->fields[index].id, escaped[index]);
                    if (amount < 0 || (size_t)amount >= capacity - used) return -1;
                    used += (size_t)amount;
                }
            }
            amount = snprintf(output + used, capacity - used, "</parameter>");
            if (amount < 0 || (size_t)amount >= capacity - used) return -1;
            used += (size_t)amount;
        }
        amount = snprintf(output + used, capacity - used, "</parameter></section>");
        return amount < 0 || (size_t)amount >= capacity - used ? -1 : 0;
    }
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
