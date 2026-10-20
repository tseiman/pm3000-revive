#define _POSIX_C_SOURCE 200809L

#include "token_auth.h"
#include "sha256.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#define MAX_STORE_BYTES (128U * 1024U)
#define MAX_TOKENS 128U

struct cursor {
    const unsigned char *data;
    size_t length;
    size_t offset;
};

struct record_key {
    char id[27];
    char digest[65];
};

static int expect(struct cursor *cursor, const char *literal) {
    size_t length = strlen(literal);
    if (cursor->offset + length > cursor->length ||
        memcmp(cursor->data + cursor->offset, literal, length) != 0) return -1;
    cursor->offset += length;
    return 0;
}

static int hex_value(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

static int append_codepoint(char *output, size_t capacity, size_t *used, uint32_t value) {
    unsigned char bytes[4];
    size_t count;
    if (value == 0U || value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU)) return -1;
    if (value < 0x80U) { bytes[0] = (unsigned char)value; count = 1; }
    else if (value < 0x800U) {
        bytes[0] = (unsigned char)(0xc0U | (value >> 6)); bytes[1] = (unsigned char)(0x80U | (value & 63U)); count = 2;
    } else if (value < 0x10000U) {
        bytes[0] = (unsigned char)(0xe0U | (value >> 12)); bytes[1] = (unsigned char)(0x80U | ((value >> 6) & 63U));
        bytes[2] = (unsigned char)(0x80U | (value & 63U)); count = 3;
    } else {
        bytes[0] = (unsigned char)(0xf0U | (value >> 18)); bytes[1] = (unsigned char)(0x80U | ((value >> 12) & 63U));
        bytes[2] = (unsigned char)(0x80U | ((value >> 6) & 63U)); bytes[3] = (unsigned char)(0x80U | (value & 63U)); count = 4;
    }
    if (*used + count >= capacity) return -1;
    memcpy(output + *used, bytes, count); *used += count; output[*used] = '\0';
    return 0;
}

static int parse_string(struct cursor *cursor, char *output, size_t capacity) {
    size_t used = 0;
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != '"') return -1;
    output[0] = '\0';
    while (cursor->offset < cursor->length) {
        unsigned char value = cursor->data[cursor->offset++];
        if (value == '"') return 0;
        if (value < 0x20U) return -1;
        if (value == '\\') {
            uint32_t codepoint;
            int index;
            if (cursor->offset >= cursor->length) return -1;
            value = cursor->data[cursor->offset++];
            if (value == '"' || value == '\\' || value == '/') codepoint = value;
            else if (value == 'b') codepoint = '\b';
            else if (value == 'f') codepoint = '\f';
            else if (value == 'n') codepoint = '\n';
            else if (value == 'r') codepoint = '\r';
            else if (value == 't') codepoint = '\t';
            else if (value == 'u') {
                codepoint = 0;
                for (index = 0; index < 4; ++index) {
                    int part;
                    if (cursor->offset >= cursor->length || (part = hex_value(cursor->data[cursor->offset++])) < 0) return -1;
                    codepoint = (codepoint << 4) | (uint32_t)part;
                }
                if (codepoint >= 0xd800U && codepoint <= 0xdbffU) {
                    uint32_t low = 0U;
                    if (cursor->offset + 6U > cursor->length ||
                        cursor->data[cursor->offset++] != '\\' ||
                        cursor->data[cursor->offset++] != 'u') return -1;
                    for (index = 0; index < 4; ++index) {
                        int part = hex_value(cursor->data[cursor->offset++]);
                        if (part < 0) return -1;
                        low = (low << 4) | (uint32_t)part;
                    }
                    if (low < 0xdc00U || low > 0xdfffU) return -1;
                    codepoint = 0x10000U + ((codepoint - 0xd800U) << 10) + (low - 0xdc00U);
                } else if (codepoint >= 0xdc00U && codepoint <= 0xdfffU) return -1;
            } else return -1;
            if (append_codepoint(output, capacity, &used, codepoint) != 0) return -1;
        } else {
            if (used + 1U >= capacity) return -1;
            output[used++] = (char)value; output[used] = '\0';
        }
    }
    return -1;
}

static int parse_uint64(struct cursor *cursor, uint64_t *value) {
    size_t start = cursor->offset;
    uint64_t result = 0;
    if (start >= cursor->length || cursor->data[start] < '0' || cursor->data[start] > '9') return -1;
    if (cursor->data[start] == '0' && start + 1U < cursor->length &&
        cursor->data[start + 1U] >= '0' && cursor->data[start + 1U] <= '9') return -1;
    while (cursor->offset < cursor->length && cursor->data[cursor->offset] >= '0' && cursor->data[cursor->offset] <= '9') {
        unsigned int digit = cursor->data[cursor->offset++] - '0';
        if (result > (UINT64_MAX - digit) / 10U) return -1;
        result = result * 10U + digit;
    }
    *value = result;
    return 0;
}

static int opaque_id(const char *value) {
    size_t index;
    if (strlen(value) != PM3000_OPAQUE_ID_LENGTH) return 0;
    for (index = 0; index < PM3000_OPAQUE_ID_LENGTH; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int token_id(const char *value) {
    return strlen(value) == 26U && memcmp(value, "tok_", 4) == 0 && opaque_id(value + 4);
}

static int unicode_trim_space(uint32_t value) {
    return (value >= 0x09U && value <= 0x0dU) || (value >= 0x1cU && value <= 0x20U) ||
           value == 0x85U || value == 0xa0U || value == 0x1680U ||
           (value >= 0x2000U && value <= 0x200aU) || value == 0x2028U ||
           value == 0x2029U || value == 0x202fU || value == 0x205fU || value == 0x3000U;
}

static int valid_label(const char *label) {
    const unsigned char *value = (const unsigned char *)label;
    size_t length = strlen(label);
    size_t offset = 0;
    unsigned int characters = 0;
    uint32_t first_codepoint = 0U, last_codepoint = 0U;
    if (length == 0U || length > 128U) return 0;
    while (offset < length) {
        unsigned char first = value[offset++];
        uint32_t codepoint;
        uint32_t minimum;
        size_t remaining;
        if (first < 0x80U) { codepoint = first; remaining = 0; minimum = 0U; }
        else if (first >= 0xc2U && first <= 0xdfU) { codepoint = first & 0x1fU; remaining = 1; minimum = 0x80U; }
        else if (first >= 0xe0U && first <= 0xefU) { codepoint = first & 0x0fU; remaining = 2; minimum = 0x800U; }
        else if (first >= 0xf0U && first <= 0xf4U) { codepoint = first & 0x07U; remaining = 3; minimum = 0x10000U; }
        else return 0;
        if (offset + remaining > length) return 0;
        while (remaining-- > 0U) {
            unsigned char next = value[offset++];
            if ((next & 0xc0U) != 0x80U) return 0;
            codepoint = (codepoint << 6) | (next & 0x3fU);
        }
        if (codepoint < minimum || codepoint < 0x20U || codepoint == 0x7fU ||
            (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU) return 0;
        if (characters == 0U) first_codepoint = codepoint;
        last_codepoint = codepoint;
        ++characters;
    }
    return characters >= 1U && characters <= 64U && !unicode_trim_space(first_codepoint) &&
           !unicode_trim_space(last_codepoint);
}

static int valid_created(const char *value) {
    static const unsigned int days[] = {0U, 31U, 28U, 31U, 30U, 31U, 30U,
                                        31U, 31U, 30U, 31U, 30U, 31U};
    unsigned int year, month, day, hour, minute, second, maximum;
    size_t index;
    if (strlen(value) != 20U || value[4] != '-' || value[7] != '-' ||
        value[10] != 'T' || value[13] != ':' || value[16] != ':' || value[19] != 'Z') return 0;
    for (index = 0U; index < 19U; ++index) {
        if (index != 4U && index != 7U && index != 10U && index != 13U &&
            index != 16U && (value[index] < '0' || value[index] > '9')) return 0;
    }
    year = (unsigned int)(value[0] - '0') * 1000U + (unsigned int)(value[1] - '0') * 100U +
           (unsigned int)(value[2] - '0') * 10U + (unsigned int)(value[3] - '0');
    month = (unsigned int)(value[5] - '0') * 10U + (unsigned int)(value[6] - '0');
    day = (unsigned int)(value[8] - '0') * 10U + (unsigned int)(value[9] - '0');
    hour = (unsigned int)(value[11] - '0') * 10U + (unsigned int)(value[12] - '0');
    minute = (unsigned int)(value[14] - '0') * 10U + (unsigned int)(value[15] - '0');
    second = (unsigned int)(value[17] - '0') * 10U + (unsigned int)(value[18] - '0');
    if (year == 0U || month == 0U || month > 12U) return 0;
    maximum = days[month];
    if (month == 2U && ((year % 4U == 0U && year % 100U != 0U) || year % 400U == 0U)) ++maximum;
    return day >= 1U && day <= maximum && hour <= 23U && minute <= 59U && second <= 59U;
}

static int digest_value(const char *value) {
    size_t index;
    if (strlen(value) != 64U) return 0;
    for (index = 0; index < 64U; ++index) if (!((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return 1;
}

static int constant_equal(const char *left, const char *right, size_t length) {
    unsigned char difference = 0;
    size_t index;
    for (index = 0; index < length; ++index) difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    return difference == 0;
}

static void digest_plaintext(const char *plaintext, char output[65]) {
    static const char hex[] = "0123456789abcdef";
    unsigned char digest[32];
    size_t index;
    sha256_bytes(plaintext, strlen(plaintext), digest);
    for (index = 0; index < 32U; ++index) {
        output[index * 2U] = hex[digest[index] >> 4];
        output[index * 2U + 1U] = hex[digest[index] & 15U];
    }
    output[64] = '\0';
}

static int scope_level(const char *scope) {
    if (strcmp(scope, "read") == 0) return 1;
    if (strcmp(scope, "control") == 0) return 2;
    if (strcmp(scope, "admin") == 0) return 3;
    return 0;
}

static int parse_store(const unsigned char *data, size_t length, const char *plaintext,
                       const char *required_scope, const char *required_outlet,
                       pm3000_authorization *authorization) {
    struct cursor cursor = {data, length, 0};
    struct record_key keys[MAX_TOKENS];
    unsigned int token_count = 0;
    unsigned int enabled_admins = 0;
    char presented[65];
    uint64_t generation;
    uint64_t schema;
    int required_level = scope_level(required_scope);
    int matched = 0;
    if (required_level == 0 || strlen(plaintext) != 47U || memcmp(plaintext, "pm3_", 4) != 0) return 0;
    digest_plaintext(plaintext, presented);
    if (expect(&cursor, "{\"generation\":") != 0 || parse_uint64(&cursor, &generation) != 0 || generation < 1U || generation > INT64_MAX ||
        expect(&cursor, ",\"schemaVersion\":") != 0 || parse_uint64(&cursor, &schema) != 0 || schema != 1U ||
        expect(&cursor, ",\"tokens\":[") != 0) return -1;
    while (cursor.offset < cursor.length && cursor.data[cursor.offset] != ']') {
        char created[32], digest[65], id[27], label[129], scope[16];
        char outlets[PM3000_MAX_ALLOWLIST][PM3000_OPAQUE_ID_LENGTH + 1U];
        unsigned int outlet_count = 0;
        int unrestricted = 0;
        int enabled;
        unsigned int index;
        if (token_count > 0U && expect(&cursor, ",") != 0) return -1;
        if (expect(&cursor, "{\"createdAt\":") != 0 || parse_string(&cursor, created, sizeof(created)) != 0 ||
            expect(&cursor, ",\"digest\":") != 0 || parse_string(&cursor, digest, sizeof(digest)) != 0 ||
            expect(&cursor, ",\"enabled\":") != 0) return -1;
        if (expect(&cursor, "true") == 0) enabled = 1;
        else { if (expect(&cursor, "false") != 0) return -1; enabled = 0; }
        if (expect(&cursor, ",\"id\":") != 0 || parse_string(&cursor, id, sizeof(id)) != 0 ||
            expect(&cursor, ",\"label\":") != 0 || parse_string(&cursor, label, sizeof(label)) != 0 ||
            expect(&cursor, ",\"outlets\":") != 0) return -1;
        if (cursor.offset + 4U <= cursor.length && memcmp(cursor.data + cursor.offset, "null", 4) == 0) {
            cursor.offset += 4U; unrestricted = 1;
        } else {
            if (expect(&cursor, "[") != 0) return -1;
            while (cursor.offset < cursor.length && cursor.data[cursor.offset] != ']') {
                if (outlet_count > 0U && expect(&cursor, ",") != 0) return -1;
                if (outlet_count >= PM3000_MAX_ALLOWLIST ||
                    parse_string(&cursor, outlets[outlet_count], sizeof(outlets[outlet_count])) != 0 ||
                    !opaque_id(outlets[outlet_count]) ||
                    (outlet_count > 0U && strcmp(outlets[outlet_count - 1U], outlets[outlet_count]) >= 0)) return -1;
                ++outlet_count;
            }
            if (expect(&cursor, "]") != 0) return -1;
        }
        if (expect(&cursor, ",\"scope\":") != 0 || parse_string(&cursor, scope, sizeof(scope)) != 0 || expect(&cursor, "}") != 0) return -1;
        if (token_count >= MAX_TOKENS || !valid_created(created) || !digest_value(digest) ||
            !token_id(id) || !valid_label(label) || scope_level(scope) == 0) return -1;
        for (index = 0; index < token_count; ++index) {
            if (strcmp(keys[index].id, id) == 0 || strcmp(keys[index].digest, digest) == 0) return -1;
        }
        strcpy(keys[token_count].id, id); strcpy(keys[token_count].digest, digest);
        ++token_count;
        if (enabled && strcmp(scope, "admin") == 0) ++enabled_admins;
        if (constant_equal(digest, presented, 64U)) {
            authorization->authenticated = enabled;
            matched = enabled && scope_level(scope) >= required_level;
            authorization->unrestricted = unrestricted;
            authorization->outlet_count = outlet_count;
            for (index = 0; index < outlet_count; ++index) strcpy(authorization->outlets[index], outlets[index]);
        }
    }
    if (expect(&cursor, "]}") != 0) return -1;
    if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '\n') ++cursor.offset;
    if (cursor.offset != cursor.length || token_count == 0U || enabled_admins == 0U) return -1;
    if (matched && required_outlet != NULL) {
        unsigned int index;
        matched = authorization->unrestricted;
        for (index = 0; !matched && index < authorization->outlet_count; ++index) {
            if (strcmp(authorization->outlets[index], required_outlet) == 0) matched = 1;
        }
    }
    authorization->authorized = matched;
    return 0;
}

static int split_path(const char *path, char *directory, size_t directory_size, const char **name) {
    const char *slash = strrchr(path, '/');
    size_t amount;
    if (slash == NULL || slash[1] == '\0') return -1;
    amount = (size_t)(slash - path);
    if (amount == 0U) amount = 1U;
    if (amount >= directory_size) return -1;
    memcpy(directory, path, amount); directory[amount] = '\0'; *name = slash + 1;
    return 0;
}

int pm3000_authorize(const char *store_path, const char *plaintext,
                     const char *required_scope, const char *outlet_id,
                     pm3000_authorization *authorization,
                     char *error, unsigned int error_size) {
    char directory[PATH_MAX];
    const char *name;
    char lock_name[NAME_MAX + 1U];
    int directory_fd = -1, lock_fd = -1, store_fd = -1;
    struct stat metadata, current;
    unsigned char *buffer = NULL;
    size_t used = 0;
    int result = -1;
    memset(authorization, 0, sizeof(*authorization));
    if (split_path(store_path, directory, sizeof(directory), &name) != 0 || strlen(name) > NAME_MAX - 5U) goto cleanup;
    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (directory_fd < 0 || fstat(directory_fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode) ||
        metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0700U) goto cleanup;
    if (snprintf(lock_name, sizeof(lock_name), "%s.lock", name) < 0) goto cleanup;
    lock_fd = openat(directory_fd, lock_name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (lock_fd < 0 || fstat(lock_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1U ||
        metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0600U || flock(lock_fd, LOCK_SH) != 0 ||
        fstatat(directory_fd, lock_name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino) goto cleanup;
    store_fd = openat(directory_fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (store_fd < 0 || fstat(store_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1U ||
        metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0600U || metadata.st_size <= 0 || metadata.st_size > MAX_STORE_BYTES ||
        fstatat(directory_fd, name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino) goto cleanup;
    buffer = (unsigned char *)malloc((size_t)metadata.st_size);
    if (buffer == NULL) goto cleanup;
    while (used < (size_t)metadata.st_size) {
        ssize_t amount = read(store_fd, buffer + used, (size_t)metadata.st_size - used);
        if (amount <= 0) goto cleanup;
        used += (size_t)amount;
    }
    result = parse_store(buffer, used, plaintext, required_scope, outlet_id, authorization);
cleanup:
    free(buffer);
    if (store_fd >= 0) close(store_fd);
    if (lock_fd >= 0) { (void)flock(lock_fd, LOCK_UN); close(lock_fd); }
    if (directory_fd >= 0) close(directory_fd);
    if (result < 0) (void)snprintf(error, error_size, "token store rejected");
    return result;
}
