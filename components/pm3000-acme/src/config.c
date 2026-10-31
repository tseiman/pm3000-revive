#include "pm3000_acme_config.h"
#include "pm3000_acme_json.h"
#include "pm3000_acme_url.h"

#include <string.h>

static void clear_config(struct pm3000_acme_runtime_config *config)
{
    unsigned int index;
    config->enabled = 0;
    config->directory_url[0] = '\0';
    config->ca_file[0] = '\0';
    config->dns_name_count = 0U;
    for (index = 0U; index < PM3000_ACME_MAX_IDENTIFIERS; ++index)
        config->dns_names[index][0] = '\0';
}

static int safe_absolute_path(const char *path)
{
    unsigned int index = 0U;
    if (path == (const char *)0 || path[0] != '/') return 0;
    while (path[index] != '\0') {
        unsigned char value = (unsigned char)path[index];
        if (value < 0x21U || value > 0x7eU || value == '\\') return 0;
        if (path[index] == '.' && path[index + 1U] == '.' &&
            (index == 0U || path[index - 1U] == '/') &&
            (path[index + 2U] == '/' || path[index + 2U] == '\0')) return 0;
        if (++index > PM3000_ACME_CA_PATH_MAX) return 0;
    }
    return index > 1U;
}

int pm3000_acme_config_parse(const unsigned char *json,
                             unsigned int json_length,
                             struct pm3000_acme_runtime_config *config)
{
    struct pm3000_acme_json_document document;
    struct pm3000_acme_url directory;
    int enabled_token;
    int directory_token;
    int ca_token;
    int names_token;
    int name_token;
    unsigned int count;
    unsigned int index;
    unsigned int previous;
    char raw_name[PM3000_ACME_HOST_MAX + 1U];
    if (config == (struct pm3000_acme_runtime_config *)0)
        return PM3000_ACME_CONFIG_INVALID;
    clear_config(config);
    if (pm3000_acme_json_parse(json, json_length, &document) !=
            PM3000_ACME_JSON_OK ||
        document.tokens[0].type != PM3000_ACME_JSON_OBJECT ||
        document.tokens[0].count != 4U ||
        pm3000_acme_json_object_get(&document, 0, "enabled",
                                    &enabled_token) != PM3000_ACME_JSON_OK ||
        (document.tokens[enabled_token].type != PM3000_ACME_JSON_TRUE &&
         document.tokens[enabled_token].type != PM3000_ACME_JSON_FALSE) ||
        pm3000_acme_json_object_get(&document, 0, "directory_url",
                                    &directory_token) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(
            &document, directory_token, config->directory_url,
            sizeof(config->directory_url)) != PM3000_ACME_JSON_OK ||
        pm3000_acme_url_parse(config->directory_url, &directory) !=
            PM3000_ACME_URL_OK ||
        pm3000_acme_json_object_get(&document, 0, "ca_file",
                                    &ca_token) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(&document, ca_token, config->ca_file,
                                     sizeof(config->ca_file)) !=
            PM3000_ACME_JSON_OK ||
        !safe_absolute_path(config->ca_file) ||
        pm3000_acme_json_object_get(&document, 0, "dns_names",
                                    &names_token) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_array_length(&document, names_token, &count) !=
            PM3000_ACME_JSON_OK || count == 0U ||
        count > PM3000_ACME_MAX_IDENTIFIERS) goto rejected;
    config->enabled = document.tokens[enabled_token].type ==
                      PM3000_ACME_JSON_TRUE;
    for (index = 0U; index < count; ++index) {
        if (pm3000_acme_json_array_get(&document, names_token, index,
                                       &name_token) != PM3000_ACME_JSON_OK ||
            pm3000_acme_json_string_copy(&document, name_token, raw_name,
                                         sizeof(raw_name)) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_dns_name_normalize(
                raw_name, config->dns_names[index],
                sizeof(config->dns_names[index])) != PM3000_ACME_URL_OK)
            goto rejected;
        for (previous = 0U; previous < index; ++previous) {
            unsigned int offset = 0U;
            while (config->dns_names[index][offset] ==
                       config->dns_names[previous][offset] &&
                   config->dns_names[index][offset] != '\0') ++offset;
            if (config->dns_names[index][offset] == '\0' &&
                config->dns_names[previous][offset] == '\0') goto rejected;
        }
    }
    config->dns_name_count = count;
    return PM3000_ACME_CONFIG_OK;
rejected:
    clear_config(config);
    return PM3000_ACME_CONFIG_INVALID;
}

static int append_bytes(unsigned char *output, unsigned int capacity,
                        unsigned int *length, const char *text)
{
    unsigned int amount = (unsigned int)strlen(text);
    if (*length > capacity || amount > capacity - *length)
        return PM3000_ACME_CONFIG_LIMIT;
    memcpy(output + *length, text, amount);
    *length += amount;
    return PM3000_ACME_CONFIG_OK;
}

static int append_json_string(unsigned char *output, unsigned int capacity,
                              unsigned int *length, const char *text)
{
    unsigned int index;
    if (append_bytes(output, capacity, length, "\"") !=
        PM3000_ACME_CONFIG_OK) return PM3000_ACME_CONFIG_LIMIT;
    for (index = 0U; text[index] != '\0'; ++index) {
        unsigned char value = (unsigned char)text[index];
        char escaped[3];
        if (value < 0x20U || value > 0x7eU)
            return PM3000_ACME_CONFIG_INVALID;
        if (value == '"' || value == '\\') {
            escaped[0] = '\\';
            escaped[1] = (char)value;
            escaped[2] = '\0';
            if (append_bytes(output, capacity, length, escaped) !=
                PM3000_ACME_CONFIG_OK) return PM3000_ACME_CONFIG_LIMIT;
        } else {
            if (*length >= capacity) return PM3000_ACME_CONFIG_LIMIT;
            output[(*length)++] = value;
        }
    }
    return append_bytes(output, capacity, length, "\"");
}

int pm3000_acme_config_serialize(
    const struct pm3000_acme_runtime_config *config,
    unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    unsigned int index;
    unsigned int length = 0U;
    if (config == (const struct pm3000_acme_runtime_config *)0 ||
        output == (unsigned char *)0 || output_length == (unsigned int *)0 ||
        config->dns_name_count == 0U ||
        config->dns_name_count > PM3000_ACME_MAX_IDENTIFIERS)
        return PM3000_ACME_CONFIG_INVALID;
    if (append_bytes(output, output_capacity, &length, "{\"enabled\":") != 0 ||
        append_bytes(output, output_capacity, &length,
                     config->enabled ? "true" : "false") != 0 ||
        append_bytes(output, output_capacity, &length,
                     ",\"directory_url\":") != 0 ||
        append_json_string(output, output_capacity, &length,
                           config->directory_url) != 0 ||
        append_bytes(output, output_capacity, &length, ",\"ca_file\":") != 0 ||
        append_json_string(output, output_capacity, &length,
                           config->ca_file) != 0 ||
        append_bytes(output, output_capacity, &length, ",\"dns_names\":[") != 0)
        return PM3000_ACME_CONFIG_LIMIT;
    for (index = 0U; index < config->dns_name_count; ++index) {
        if (index != 0U &&
            append_bytes(output, output_capacity, &length, ",") != 0)
            return PM3000_ACME_CONFIG_LIMIT;
        if (append_json_string(output, output_capacity, &length,
                               config->dns_names[index]) != 0)
            return PM3000_ACME_CONFIG_LIMIT;
    }
    if (append_bytes(output, output_capacity, &length, "]}\n") != 0)
        return PM3000_ACME_CONFIG_LIMIT;
    *output_length = length;
    return PM3000_ACME_CONFIG_OK;
}
