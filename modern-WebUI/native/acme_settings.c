#include "acme_settings.h"

#include <stdio.h>
#include <string.h>

struct cursor { const unsigned char *data; size_t length; size_t offset; };

static void space(struct cursor *cursor)
{
    while (cursor->offset < cursor->length &&
           (cursor->data[cursor->offset] == ' ' || cursor->data[cursor->offset] == '\t' ||
            cursor->data[cursor->offset] == '\r' || cursor->data[cursor->offset] == '\n'))
        ++cursor->offset;
}

static int character(struct cursor *cursor, unsigned char expected)
{
    space(cursor);
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset] != expected) return -1;
    ++cursor->offset;
    return 0;
}

static int hex(unsigned char value)
{
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int string_value(struct cursor *cursor, char *output, size_t capacity)
{
    size_t used = 0U;
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != '"') return -1;
    while (cursor->offset < cursor->length) {
        unsigned char value = cursor->data[cursor->offset++];
        if (value == '"') {
            if (used >= capacity) return -1;
            output[used] = '\0';
            return 0;
        }
        if (value < 0x20U || value >= 0x80U) return -1;
        if (value == '\\') {
            unsigned int codepoint = 0U;
            int index;
            if (cursor->offset >= cursor->length) return -1;
            value = cursor->data[cursor->offset++];
            if (value == '"' || value == '\\' || value == '/') { }
            else if (value == 'b') value = '\b';
            else if (value == 'f') value = '\f';
            else if (value == 'n') value = '\n';
            else if (value == 'r') value = '\r';
            else if (value == 't') value = '\t';
            else if (value == 'u') {
                for (index = 0; index < 4; ++index) {
                    int part;
                    if (cursor->offset >= cursor->length ||
                        (part = hex(cursor->data[cursor->offset++])) < 0) return -1;
                    codepoint = codepoint * 16U + (unsigned int)part;
                }
                if (codepoint == 0U || codepoint >= 0x80U) return -1;
                value = (unsigned char)codepoint;
            } else return -1;
        }
        if (value < 0x20U || used + 1U >= capacity) return -1;
        output[used++] = (char)value;
    }
    return -1;
}

static int boolean_value(struct cursor *cursor, int *value)
{
    if (cursor->offset + 4U <= cursor->length &&
        memcmp(cursor->data + cursor->offset, "true", 4U) == 0) {
        cursor->offset += 4U; *value = 1; return 0;
    }
    if (cursor->offset + 5U <= cursor->length &&
        memcmp(cursor->data + cursor->offset, "false", 5U) == 0) {
        cursor->offset += 5U; *value = 0; return 0;
    }
    return -1;
}

static int valid_hostname_range(const char *value, size_t length)
{
    size_t index, label_length = 0U;
    if (length == 0U || length > 253U) return 0;
    for (index = 0U; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c == '.') {
            if (label_length == 0U || value[index - 1U] == '-') return 0;
            label_length = 0U; continue;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-') ||
            (label_length == 0U && c == '-') || ++label_length > 63U) return 0;
    }
    return label_length != 0U && value[length - 1U] != '-';
}

static int valid_directory(const char *value)
{
    size_t length = strlen(value), slash = 8U, colon = 0U, index, host_end;
    unsigned int port = 0U;
    if (strncmp(value, "https://", 8U) != 0 || length <= 8U) return 0;
    while (slash < length && value[slash] != '/') ++slash;
    if (slash == length) return 0;
    for (index = 8U; index < slash; ++index) {
        if (value[index] == '@' || value[index] == '[' || value[index] == ']') return 0;
        if (value[index] == ':') { if (colon != 0U) return 0; colon = index; }
    }
    host_end = colon == 0U ? slash : colon;
    if (!valid_hostname_range(value + 8U, host_end - 8U)) return 0;
    if (colon != 0U) {
        if (colon + 1U == slash) return 0;
        for (index = colon + 1U; index < slash; ++index) {
            unsigned int digit;
            if (value[index] < '0' || value[index] > '9') return 0;
            digit = (unsigned int)(value[index] - '0');
            if (port > 6553U || (port == 6553U && digit > 5U)) return 0;
            port = port * 10U + digit;
        }
        if (port == 0U) return 0;
    }
    if (length - slash > 1024U) return 0;
    for (index = slash; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c < 0x21U || c > 0x7eU || c == '?' || c == '#' || c == '\\' || c == '%') return 0;
    }
    return 1;
}

static int valid_ca_file(const char *value)
{
    size_t index;
    if (value[0] != '/' || value[1] == '\0') return 0;
    for (index = 1U; value[index] != '\0'; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-' || c == '/'))
            return 0;
        if (c == '/' && (value[index - 1U] == '/' || value[index + 1U] == '\0')) return 0;
    }
    return 1;
}

static int valid_dns_name(char *value)
{
    size_t length = strlen(value), index, label_length = 0U;
    if (length == 0U || length > 253U) return 0;
    for (index = 0U; index < length; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c == '.') {
            if (label_length == 0U || value[index - 1U] == '-') return 0;
            label_length = 0U;
            continue;
        }
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-') ||
            (label_length == 0U && c == '-') || ++label_length > 63U) return 0;
        if (c >= 'A' && c <= 'Z') value[index] = (char)(c + ('a' - 'A'));
    }
    return label_length != 0U && value[length - 1U] != '-';
}

static int names_value(struct cursor *cursor, struct pm3000_acme_setting *setting)
{
    unsigned int count = 0U, previous;
    int first = 1;
    if (character(cursor, '[') != 0) return -1;
    for (;;) {
        space(cursor);
        if (cursor->offset < cursor->length && cursor->data[cursor->offset] == ']') {
            ++cursor->offset; break;
        }
        if (!first && character(cursor, ',') != 0) return -1;
        first = 0; space(cursor);
        if (count >= PM3000_ACME_DNS_LIMIT ||
            string_value(cursor, setting->dns_names[count], PM3000_ACME_DNS_CAPACITY) != 0 ||
            !valid_dns_name(setting->dns_names[count])) return -1;
        for (previous = 0U; previous < count; ++previous)
            if (strcmp(setting->dns_names[previous], setting->dns_names[count]) == 0) return -1;
        ++count;
    }
    if (count == 0U) return -1;
    setting->dns_name_count = count;
    return 0;
}

static int parse_config(const unsigned char *data, size_t length,
                        struct pm3000_acme_setting *setting, int api)
{
    struct cursor cursor = {data, length, 0U};
    unsigned int seen = 0U;
    int first = 1;
    memset(setting, 0, sizeof(*setting));
    if (length == 0U || character(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[32];
        unsigned int bit;
        space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset; break;
        }
        if (!first && character(&cursor, ',') != 0) return -1;
        first = 0; space(&cursor);
        if (string_value(&cursor, key, sizeof(key)) != 0 || character(&cursor, ':') != 0) return -1;
        space(&cursor);
        if (strcmp(key, "enabled") == 0) {
            bit = 1U;
            if ((seen & bit) != 0U || boolean_value(&cursor, &setting->enabled) != 0) return -1;
        } else if (strcmp(key, api ? "directoryUrl" : "directory_url") == 0) {
            bit = 2U;
            if ((seen & bit) != 0U || string_value(&cursor, setting->directory_url,
                    sizeof(setting->directory_url)) != 0 || !valid_directory(setting->directory_url)) return -1;
        } else if (!api && strcmp(key, "ca_file") == 0) {
            bit = 4U;
            if ((seen & bit) != 0U || string_value(&cursor, setting->ca_file,
                    sizeof(setting->ca_file)) != 0 || !valid_ca_file(setting->ca_file)) return -1;
        } else if (strcmp(key, api ? "dnsNames" : "dns_names") == 0) {
            bit = 8U;
            if ((seen & bit) != 0U || names_value(&cursor, setting) != 0) return -1;
        } else return -1;
        seen |= bit;
    }
    space(&cursor);
    return cursor.offset == cursor.length && seen == (api ? 11U : 15U) ? 0 : -1;
}

int pm3000_acme_parse_cli_config(const unsigned char *data, size_t length,
                                  struct pm3000_acme_setting *setting)
{
    return data != NULL && setting != NULL ? parse_config(data, length, setting, 0) : -1;
}

int pm3000_acme_parse_api_replacement(const unsigned char *data, size_t length,
                                      struct pm3000_acme_setting *setting)
{
    return data != NULL && setting != NULL ? parse_config(data, length, setting, 1) : -1;
}

static int append(unsigned char *output, size_t capacity, size_t *used, const char *text)
{
    size_t amount = strlen(text);
    if (*used > capacity || amount > capacity - *used) return -1;
    memcpy(output + *used, text, amount); *used += amount;
    return 0;
}

static int append_string(unsigned char *output, size_t capacity, size_t *used, const char *value)
{
    if (append(output, capacity, used, "\"") != 0) return -1;
    while (*value != '\0') {
        char escaped[3] = {0, 0, 0};
        unsigned char c = (unsigned char)*value++;
        if (c < 0x20U || c >= 0x80U) return -1;
        if (c == '"' || c == '\\') { escaped[0] = '\\'; escaped[1] = (char)c; }
        else escaped[0] = (char)c;
        if (append(output, capacity, used, escaped) != 0) return -1;
    }
    return append(output, capacity, used, "\"");
}

int pm3000_acme_serialize_cli_config(const struct pm3000_acme_setting *setting,
                                     unsigned char *output, size_t capacity,
                                     size_t *length)
{
    size_t used = 0U;
    unsigned int index;
    if (setting == NULL || output == NULL || length == NULL ||
        setting->dns_name_count == 0U || setting->dns_name_count > PM3000_ACME_DNS_LIMIT) return -1;
    if (append(output, capacity, &used, setting->enabled ? "{\"enabled\":true,\"directory_url\":" :
                                                       "{\"enabled\":false,\"directory_url\":") != 0 ||
        append_string(output, capacity, &used, setting->directory_url) != 0 ||
        append(output, capacity, &used, ",\"ca_file\":") != 0 ||
        append_string(output, capacity, &used, setting->ca_file) != 0 ||
        append(output, capacity, &used, ",\"dns_names\":[") != 0) return -1;
    for (index = 0U; index < setting->dns_name_count; ++index) {
        if ((index != 0U && append(output, capacity, &used, ",") != 0) ||
            append_string(output, capacity, &used, setting->dns_names[index]) != 0) return -1;
    }
    if (append(output, capacity, &used, "]}\n") != 0) return -1;
    *length = used;
    return 0;
}

int pm3000_acme_parse_status(
    const unsigned char *data, size_t length,
    struct pm3000_acme_renewal_status *status)
{
    static const char *const states[] = {"never_run", "starting", "running", "succeeded",
                                         "failed", "durability_uncertain", "unknown"};
    static const char *const phases[] = {
        "directory", "nonce", "account", "order", "authorization",
        "challenge_publication", "challenge_acceptance", "challenge_poll",
        "finalize", "certificate_download", "certificate_validation",
        "certificate_publication"
    };
    static const char *const reasons[] = {
        "tls", "http", "parse", "io", "rejected", "timeout",
        "validation", "publication"
    };
    unsigned int index;
    unsigned int reason_index;
    if (data == NULL || status == NULL) return -1;
    memset(status, 0, sizeof(*status));
    for (index = 0U; index < sizeof(states) / sizeof(states[0]); ++index) {
        char expected[64];
        int amount = snprintf(expected, sizeof(expected), "{\"state\":\"%s\"}\n", states[index]);
        if (amount > 0 && length == (size_t)amount && memcmp(data, expected, length) == 0) {
            strcpy(status->state, states[index]); return 0;
        }
    }
    for (index = 0U; index < sizeof(phases) / sizeof(phases[0]); ++index)
        for (reason_index = 0U;
             reason_index < sizeof(reasons) / sizeof(reasons[0]);
             ++reason_index) {
            char expected[160];
            int amount = snprintf(
                expected, sizeof(expected),
                "{\"state\":\"failed\",\"phase\":\"%s\",\"reason\":\"%s\"}\n",
                phases[index], reasons[reason_index]);
            if (amount > 0 && length == (size_t)amount &&
                memcmp(data, expected, length) == 0) {
                strcpy(status->state, "failed");
                strcpy(status->phase, phases[index]);
                strcpy(status->reason, reasons[reason_index]);
                status->has_diagnostic = 1;
                return 0;
            }
        }
    return -1;
}

int pm3000_acme_setting_matches(const struct pm3000_acme_setting *left,
                                const struct pm3000_acme_setting *right,
                                int include_ca_file)
{
    unsigned int index;
    if (left->enabled != right->enabled || strcmp(left->directory_url, right->directory_url) != 0 ||
        (include_ca_file && strcmp(left->ca_file, right->ca_file) != 0) ||
        left->dns_name_count != right->dns_name_count) return 0;
    for (index = 0U; index < left->dns_name_count; ++index)
        if (strcmp(left->dns_names[index], right->dns_names[index]) != 0) return 0;
    return 1;
}

int pm3000_acme_valid_etag(const char *etag)
{
    size_t index;
    if (etag == NULL || strlen(etag) != 66U || etag[0] != '"' || etag[65] != '"') return 0;
    for (index = 1U; index < 65U; ++index)
        if (!((etag[index] >= '0' && etag[index] <= '9') ||
              (etag[index] >= 'a' && etag[index] <= 'f'))) return 0;
    return 1;
}

int pm3000_acme_is_managed_ca_file(const char *path)
{
    static const char root[] = "/mnt/hdUser/pm3000-revive/";
    static const char relative[] = "acme/trust/managed-ca.pem";
    size_t root_length;
    size_t relative_length;
    if (path == NULL) return 0;
    root_length = sizeof(root) - 1U;
    relative_length = sizeof(relative) - 1U;
    return strlen(path) == root_length + relative_length &&
           memcmp(path, root, root_length) == 0 &&
           memcmp(path + root_length, relative, relative_length) == 0;
}
