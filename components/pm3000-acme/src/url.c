#include "pm3000_acme_url.h"

#define HTTPS_PREFIX "https://"
#define HTTPS_PREFIX_LENGTH 8U
#define URL_SCAN_MAX (HTTPS_PREFIX_LENGTH + PM3000_ACME_HOST_MAX + 6U + PM3000_ACME_PATH_MAX)

static int ascii_is_digit(char value)
{
    return value >= '0' && value <= '9';
}

static int ascii_is_alpha(char value)
{
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z');
}

static char ascii_lower(char value)
{
    if (value >= 'A' && value <= 'Z') return (char)(value + ('a' - 'A'));
    return value;
}

static int prefix_is_https(const char *input)
{
    unsigned int index;
    for (index = 0U; index < HTTPS_PREFIX_LENGTH; ++index) {
        if (input[index] != HTTPS_PREFIX[index]) return 0;
    }
    return 1;
}

static int hostname_is_valid(const char *host, unsigned int length)
{
    unsigned int index;
    unsigned int label_length = 0U;

    if (length == 0U || length > PM3000_ACME_HOST_MAX) return 0;
    for (index = 0U; index < length; ++index) {
        char value = host[index];
        if (value == '.') {
            if (label_length == 0U || host[index - 1U] == '-') return 0;
            label_length = 0U;
            continue;
        }
        if (!ascii_is_alpha(value) && !ascii_is_digit(value) && value != '-') {
            return 0;
        }
        if (label_length == 0U && value == '-') return 0;
        ++label_length;
        if (label_length > 63U) return 0;
    }
    return label_length != 0U && host[length - 1U] != '-';
}

int pm3000_acme_dns_name_normalize(const char *input, char *output,
                                   unsigned int output_capacity)
{
    unsigned int length = 0U;
    unsigned int index;
    if (output == (char *)0 || output_capacity == 0U) return PM3000_ACME_URL_INVALID;
    if (input == (const char *)0) {
        output[0] = '\0';
        return PM3000_ACME_URL_INVALID;
    }
    while (length <= PM3000_ACME_HOST_MAX && input[length] != '\0') ++length;
    if (!hostname_is_valid(input, length) || length + 1U > output_capacity) {
        output[0] = '\0';
        return PM3000_ACME_URL_INVALID;
    }
    for (index = 0U; index < length; ++index) output[index] = ascii_lower(input[index]);
    output[length] = '\0';
    return PM3000_ACME_URL_OK;
}

static int path_is_valid(const char *path, unsigned int length)
{
    unsigned int index;
    if (length == 0U || length > PM3000_ACME_PATH_MAX || path[0] != '/') {
        return 0;
    }
    for (index = 0U; index < length; ++index) {
        unsigned char value = (unsigned char)path[index];
        if (value < 0x21U || value > 0x7eU || value == '?' || value == '#' ||
            value == '\\' || value == '%') {
            return 0;
        }
    }
    return 1;
}

static int invalid(struct pm3000_acme_url *output)
{
    if (output != (struct pm3000_acme_url *)0) {
        output->host[0] = '\0';
        output->port = 0U;
        output->path[0] = '\0';
    }
    return PM3000_ACME_URL_INVALID;
}

int pm3000_acme_url_same_origin(const struct pm3000_acme_url *left,
                                const struct pm3000_acme_url *right)
{
    unsigned int index = 0U;
    if (left == (const struct pm3000_acme_url *)0 ||
        right == (const struct pm3000_acme_url *)0 ||
        left->port != right->port) {
        return 0;
    }
    while (left->host[index] != '\0' && right->host[index] != '\0') {
        if (left->host[index] != right->host[index]) return 0;
        ++index;
    }
    return left->host[index] == '\0' && right->host[index] == '\0';
}

int pm3000_acme_url_parse(const char *input, struct pm3000_acme_url *output)
{
    unsigned int length = 0U;
    unsigned int slash;
    unsigned int colon = 0U;
    unsigned int host_end;
    unsigned int host_length;
    unsigned int path_length;
    unsigned int index;
    unsigned int port = 443U;

    if (input == (const char *)0 || output == (struct pm3000_acme_url *)0) {
        return PM3000_ACME_URL_INVALID;
    }
    invalid(output);
    while (length <= URL_SCAN_MAX && input[length] != '\0') ++length;
    if (length > URL_SCAN_MAX || length <= HTTPS_PREFIX_LENGTH ||
        !prefix_is_https(input)) {
        return invalid(output);
    }

    slash = HTTPS_PREFIX_LENGTH;
    while (slash < length && input[slash] != '/') ++slash;
    if (slash == length) return invalid(output);

    for (index = HTTPS_PREFIX_LENGTH; index < slash; ++index) {
        if (input[index] == '@' || input[index] == '[' || input[index] == ']') {
            return invalid(output);
        }
        if (input[index] == ':') {
            if (colon != 0U) return invalid(output);
            colon = index;
        }
    }

    host_end = colon == 0U ? slash : colon;
    host_length = host_end - HTTPS_PREFIX_LENGTH;
    if (!hostname_is_valid(input + HTTPS_PREFIX_LENGTH, host_length)) {
        return invalid(output);
    }

    if (colon != 0U) {
        if (colon + 1U == slash) return invalid(output);
        port = 0U;
        for (index = colon + 1U; index < slash; ++index) {
            unsigned int digit;
            if (!ascii_is_digit(input[index])) return invalid(output);
            digit = (unsigned int)(input[index] - '0');
            if (port > 6553U || (port == 6553U && digit > 5U)) {
                return invalid(output);
            }
            port = port * 10U + digit;
        }
        if (port == 0U) return invalid(output);
    }

    path_length = length - slash;
    if (!path_is_valid(input + slash, path_length)) return invalid(output);

    for (index = 0U; index < host_length; ++index) {
        output->host[index] = ascii_lower(input[HTTPS_PREFIX_LENGTH + index]);
    }
    output->host[host_length] = '\0';
    output->port = port;
    for (index = 0U; index < path_length; ++index) {
        output->path[index] = input[slash + index];
    }
    output->path[path_length] = '\0';
    return PM3000_ACME_URL_OK;
}
