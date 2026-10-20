#define _POSIX_C_SOURCE 200809L

#include "token_admin.h"
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
#include <time.h>
#include <unistd.h>

#define MAX_STORE_BYTES (128U * 1024U)
#define MAX_TOKENS 128U
#define MAX_OUTLETS 256U
#define BODY_LIMIT 2048U

struct cursor { const unsigned char *data; size_t length; size_t offset; };

struct token_record {
    char created[21];
    char digest[65];
    int enabled;
    char id[27];
    char label[129];
    int unrestricted;
    unsigned int outlet_count;
    char (*outlets)[23];
    char scope[8];
};

struct token_document {
    uint64_t generation;
    unsigned int count;
    struct token_record records[MAX_TOKENS];
};

struct transaction {
    int parent_directory_fd;
    int directory_fd;
    int lock_fd;
    char directory_name[NAME_MAX + 1U];
    char name[NAME_MAX + 1U];
    unsigned char *original;
    size_t original_length;
    struct token_document document;
};

struct builder { char *data; size_t used; size_t capacity; int failed; };

struct create_request {
    char label[129];
    char scope[8];
    int have_label;
    int have_scope;
    int have_outlets;
    unsigned int outlet_count;
    char outlets[MAX_OUTLETS][23];
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
    unsigned char bytes[4]; size_t count;
    if (value == 0U || value > 0x10ffffU || (value >= 0xd800U && value <= 0xdfffU)) return -1;
    if (value < 0x80U) { bytes[0] = (unsigned char)value; count = 1U; }
    else if (value < 0x800U) { bytes[0] = (unsigned char)(0xc0U | (value >> 6)); bytes[1] = (unsigned char)(0x80U | (value & 63U)); count = 2U; }
    else if (value < 0x10000U) { bytes[0] = (unsigned char)(0xe0U | (value >> 12)); bytes[1] = (unsigned char)(0x80U | ((value >> 6) & 63U)); bytes[2] = (unsigned char)(0x80U | (value & 63U)); count = 3U; }
    else { bytes[0] = (unsigned char)(0xf0U | (value >> 18)); bytes[1] = (unsigned char)(0x80U | ((value >> 12) & 63U)); bytes[2] = (unsigned char)(0x80U | ((value >> 6) & 63U)); bytes[3] = (unsigned char)(0x80U | (value & 63U)); count = 4U; }
    if (*used + count >= capacity) return -1;
    memcpy(output + *used, bytes, count); *used += count; output[*used] = '\0';
    return 0;
}

static int parse_string(struct cursor *cursor, char *output, size_t capacity) {
    size_t used = 0U;
    if (capacity == 0U || cursor->offset >= cursor->length || cursor->data[cursor->offset++] != '"') return -1;
    output[0] = '\0';
    while (cursor->offset < cursor->length) {
        unsigned char value = cursor->data[cursor->offset++];
        if (value == '"') return 0;
        if (value < 0x20U) return -1;
        if (value == '\\') {
            uint32_t codepoint; int index;
            if (cursor->offset >= cursor->length) return -1;
            value = cursor->data[cursor->offset++];
            if (value == '"' || value == '\\' || value == '/') codepoint = value;
            else if (value == 'b') codepoint = '\b';
            else if (value == 'f') codepoint = '\f';
            else if (value == 'n') codepoint = '\n';
            else if (value == 'r') codepoint = '\r';
            else if (value == 't') codepoint = '\t';
            else if (value == 'u') {
                codepoint = 0U;
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
    size_t start = cursor->offset; uint64_t result = 0U;
    if (start >= cursor->length || cursor->data[start] < '0' || cursor->data[start] > '9') return -1;
    if (cursor->data[start] == '0' && start + 1U < cursor->length && cursor->data[start + 1U] >= '0' && cursor->data[start + 1U] <= '9') return -1;
    while (cursor->offset < cursor->length && cursor->data[cursor->offset] >= '0' && cursor->data[cursor->offset] <= '9') {
        unsigned int digit = cursor->data[cursor->offset++] - '0';
        if (result > (UINT64_MAX - digit) / 10U) return -1;
        result = result * 10U + digit;
    }
    *value = result; return 0;
}

static int opaque_id(const char *value) {
    size_t index;
    if (strlen(value) != 22U) return 0;
    for (index = 0U; index < 22U; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
    }
    return 1;
}

static int valid_token_id(const char *value) { return strlen(value) == 26U && memcmp(value, "tok_", 4U) == 0 && opaque_id(value + 4); }

static int unicode_trim_space(uint32_t value) {
    return (value >= 0x09U && value <= 0x0dU) || (value >= 0x1cU && value <= 0x20U) ||
           value == 0x85U || value == 0xa0U || value == 0x1680U ||
           (value >= 0x2000U && value <= 0x200aU) || value == 0x2028U ||
           value == 0x2029U || value == 0x202fU || value == 0x205fU || value == 0x3000U;
}

static int valid_label(const char *label) {
    const unsigned char *value = (const unsigned char *)label; size_t length = strlen(label), offset = 0U; unsigned int characters = 0U; uint32_t first_codepoint = 0U, last_codepoint = 0U;
    if (length == 0U || length > 128U) return 0;
    while (offset < length) {
        unsigned char first = value[offset++]; uint32_t codepoint; size_t remaining; uint32_t minimum;
        if (first < 0x80U) { codepoint = first; remaining = 0U; minimum = 0U; }
        else if (first >= 0xc2U && first <= 0xdfU) { codepoint = first & 0x1fU; remaining = 1U; minimum = 0x80U; }
        else if (first >= 0xe0U && first <= 0xefU) { codepoint = first & 0x0fU; remaining = 2U; minimum = 0x800U; }
        else if (first >= 0xf0U && first <= 0xf4U) { codepoint = first & 0x07U; remaining = 3U; minimum = 0x10000U; }
        else return 0;
        if (offset + remaining > length) return 0;
        while (remaining-- > 0U) { unsigned char next = value[offset++]; if ((next & 0xc0U) != 0x80U) return 0; codepoint = (codepoint << 6) | (next & 0x3fU); }
        if (codepoint < minimum || codepoint < 0x20U || codepoint == 0x7fU || (codepoint >= 0xd800U && codepoint <= 0xdfffU) || codepoint > 0x10ffffU) return 0;
        if (characters == 0U) first_codepoint = codepoint;
        last_codepoint = codepoint; ++characters;
    }
    return characters >= 1U && characters <= 64U && !unicode_trim_space(first_codepoint) && !unicode_trim_space(last_codepoint);
}

static int valid_digest(const char *value) {
    size_t index; if (strlen(value) != 64U) return 0;
    for (index = 0U; index < 64U; ++index) if (!((value[index] >= '0' && value[index] <= '9') || (value[index] >= 'a' && value[index] <= 'f'))) return 0;
    return 1;
}

static int valid_created(const char *value) {
    static const unsigned int days[] = {0U, 31U, 28U, 31U, 30U, 31U, 30U,
                                        31U, 31U, 30U, 31U, 30U, 31U};
    unsigned int year, month, day, hour, minute, second, maximum;
    size_t index;
    if (strlen(value) != 20U || value[4] != '-' || value[7] != '-' || value[10] != 'T' || value[13] != ':' || value[16] != ':' || value[19] != 'Z') return 0;
    for (index = 0U; index < 19U; ++index) if (index != 4U && index != 7U && index != 10U && index != 13U && index != 16U && (value[index] < '0' || value[index] > '9')) return 0;
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

static int valid_scope(const char *scope) { return strcmp(scope, "read") == 0 || strcmp(scope, "control") == 0 || strcmp(scope, "admin") == 0; }

static void free_document(struct token_document *document) {
    unsigned int index; for (index = 0U; index < document->count; ++index) { free(document->records[index].outlets); document->records[index].outlets = NULL; }
    document->count = 0U;
}

static int parse_document(const unsigned char *data, size_t length, struct token_document *document) {
    struct cursor cursor = {data, length, 0U}; uint64_t schema; unsigned int enabled_admins = 0U;
    memset(document, 0, sizeof(*document));
    if (expect(&cursor, "{\"generation\":") != 0 || parse_uint64(&cursor, &document->generation) != 0 || document->generation < 1U || document->generation > INT64_MAX || expect(&cursor, ",\"schemaVersion\":") != 0 || parse_uint64(&cursor, &schema) != 0 || schema != 1U || expect(&cursor, ",\"tokens\":[") != 0) goto rejected;
    while (cursor.offset < cursor.length && cursor.data[cursor.offset] != ']') {
        struct token_record *record; unsigned int index;
        if (document->count >= MAX_TOKENS || (document->count > 0U && expect(&cursor, ",") != 0)) goto rejected;
        record = &document->records[document->count];
        if (expect(&cursor, "{\"createdAt\":") != 0 || parse_string(&cursor, record->created, sizeof(record->created)) != 0 || expect(&cursor, ",\"digest\":") != 0 || parse_string(&cursor, record->digest, sizeof(record->digest)) != 0 || expect(&cursor, ",\"enabled\":") != 0) goto rejected;
        if (expect(&cursor, "true") == 0) record->enabled = 1; else { if (expect(&cursor, "false") != 0) goto rejected; record->enabled = 0; }
        if (expect(&cursor, ",\"id\":") != 0 || parse_string(&cursor, record->id, sizeof(record->id)) != 0 || expect(&cursor, ",\"label\":") != 0 || parse_string(&cursor, record->label, sizeof(record->label)) != 0 || expect(&cursor, ",\"outlets\":") != 0) goto rejected;
        if (cursor.offset + 4U <= cursor.length && memcmp(cursor.data + cursor.offset, "null", 4U) == 0) { cursor.offset += 4U; record->unrestricted = 1; }
        else {
            record->outlets = (char (*)[23])calloc(MAX_OUTLETS, 23U); if (record->outlets == NULL || expect(&cursor, "[") != 0) goto rejected;
            while (cursor.offset < cursor.length && cursor.data[cursor.offset] != ']') {
                if (record->outlet_count >= MAX_OUTLETS || (record->outlet_count > 0U && expect(&cursor, ",") != 0) || parse_string(&cursor, record->outlets[record->outlet_count], 23U) != 0 || !opaque_id(record->outlets[record->outlet_count]) || (record->outlet_count > 0U && strcmp(record->outlets[record->outlet_count - 1U], record->outlets[record->outlet_count]) >= 0)) goto rejected;
                ++record->outlet_count;
            }
            if (expect(&cursor, "]") != 0) goto rejected;
        }
        if (expect(&cursor, ",\"scope\":") != 0 || parse_string(&cursor, record->scope, sizeof(record->scope)) != 0 || expect(&cursor, "}") != 0 || !valid_created(record->created) || !valid_digest(record->digest) || !valid_token_id(record->id) || !valid_label(record->label) || !valid_scope(record->scope)) goto rejected;
        for (index = 0U; index < document->count; ++index) if (strcmp(document->records[index].id, record->id) == 0 || strcmp(document->records[index].digest, record->digest) == 0) goto rejected;
        if (record->enabled && strcmp(record->scope, "admin") == 0) ++enabled_admins;
        ++document->count;
    }
    if (expect(&cursor, "]}") != 0) goto rejected;
    if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '\n') ++cursor.offset;
    if (cursor.offset != cursor.length || document->count == 0U || enabled_admins == 0U) goto rejected;
    return 0;
rejected:
    free_document(document); return -1;
}

static void digest_plaintext(const char *plaintext, char output[65]) {
    static const char hex[] = "0123456789abcdef"; unsigned char digest[32]; size_t index;
    sha256_bytes(plaintext, strlen(plaintext), digest);
    for (index = 0U; index < 32U; ++index) { output[index * 2U] = hex[digest[index] >> 4]; output[index * 2U + 1U] = hex[digest[index] & 15U]; }
    output[64] = '\0';
}

static int constant_equal(const char *left, const char *right, size_t length) {
    unsigned char difference = 0U; size_t index;
    for (index = 0U; index < length; ++index) difference |= (unsigned char)left[index] ^ (unsigned char)right[index];
    return difference == 0U;
}

static int administrator_index(const struct token_document *document, const char *plaintext) {
    char digest[65]; unsigned int index; int found = -1;
    if (plaintext == NULL || strlen(plaintext) != 47U || memcmp(plaintext, "pm3_", 4U) != 0) return -1;
    digest_plaintext(plaintext, digest);
    for (index = 0U; index < document->count; ++index) if (constant_equal(digest, document->records[index].digest, 64U) && document->records[index].enabled && strcmp(document->records[index].scope, "admin") == 0) found = (int)index;
    return found;
}

static int testing_fault(const char *point);

static int split_path(const char *path, char *directory, size_t size, const char **name) {
    const char *slash = strrchr(path, '/'); size_t amount;
    if (slash == NULL || slash[1] == '\0') return -1;
    amount = (size_t)(slash - path);
    if (amount == 0U) amount = 1U;
    if (amount >= size || strlen(slash + 1) > NAME_MAX) return -1;
    memcpy(directory, path, amount); directory[amount] = '\0'; *name = slash + 1; return 0;
}

static void close_transaction(struct transaction *transaction) {
    free_document(&transaction->document); free(transaction->original); transaction->original = NULL;
    if (transaction->lock_fd >= 0) { (void)flock(transaction->lock_fd, LOCK_UN); (void)close(transaction->lock_fd); transaction->lock_fd = -1; }
    if (transaction->directory_fd >= 0) { (void)close(transaction->directory_fd); transaction->directory_fd = -1; }
    if (transaction->parent_directory_fd >= 0) { (void)close(transaction->parent_directory_fd); transaction->parent_directory_fd = -1; }
}

static int begin_transaction(const char *path, struct transaction *transaction) {
    char directory[PATH_MAX], parent[PATH_MAX], lock_name[NAME_MAX + 1U]; const char *name, *directory_name; struct stat metadata, current, directory_metadata; int store_fd = -1; size_t used = 0U;
    memset(transaction, 0, sizeof(*transaction)); transaction->parent_directory_fd = -1; transaction->directory_fd = -1; transaction->lock_fd = -1;
    if (path == NULL || path[0] != '/' || split_path(path, directory, sizeof(directory), &name) != 0 ||
        split_path(directory, parent, sizeof(parent), &directory_name) != 0 ||
        strlen(name) > NAME_MAX - 5U) goto failure;
    strcpy(transaction->name, name);
    strcpy(transaction->directory_name, directory_name);
    transaction->parent_directory_fd = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (transaction->parent_directory_fd < 0 || fstat(transaction->parent_directory_fd, &metadata) != 0 || !S_ISDIR(metadata.st_mode)) goto failure;
    transaction->directory_fd = openat(transaction->parent_directory_fd, directory_name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (transaction->directory_fd < 0 || fstat(transaction->directory_fd, &directory_metadata) != 0 || !S_ISDIR(directory_metadata.st_mode) || directory_metadata.st_uid != getuid() || (directory_metadata.st_mode & 0777U) != 0700U ||
        fstatat(transaction->parent_directory_fd, directory_name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != directory_metadata.st_dev || current.st_ino != directory_metadata.st_ino ||
        fsync(transaction->parent_directory_fd) != 0 || testing_fault("parent_fsync")) goto failure;
    if (snprintf(lock_name, sizeof(lock_name), "%s.lock", name) < 0) goto failure;
    transaction->lock_fd = openat(transaction->directory_fd, lock_name, O_RDWR | O_NOFOLLOW | O_CLOEXEC);
    if (transaction->lock_fd < 0 || fstat(transaction->lock_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1U || metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0600U || flock(transaction->lock_fd, LOCK_EX) != 0 || fstatat(transaction->directory_fd, lock_name, &current, AT_SYMLINK_NOFOLLOW) != 0 || current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino) goto failure;
    store_fd = openat(transaction->directory_fd, name, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (store_fd < 0 || fstat(store_fd, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1U || metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0600U || metadata.st_size <= 0 || metadata.st_size > MAX_STORE_BYTES ||
        fstatat(transaction->directory_fd, name, &current, AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != metadata.st_dev || current.st_ino != metadata.st_ino) goto failure;
    transaction->original_length = (size_t)metadata.st_size; transaction->original = (unsigned char *)malloc(transaction->original_length);
    if (transaction->original == NULL) goto failure;
    while (used < transaction->original_length) { ssize_t amount = read(store_fd, transaction->original + used, transaction->original_length - used); if (amount <= 0) goto failure; used += (size_t)amount; }
    (void)close(store_fd); store_fd = -1;
    if (parse_document(transaction->original, transaction->original_length, &transaction->document) != 0) goto failure;
    return 0;
failure:
    if (store_fd >= 0) (void)close(store_fd);
    close_transaction(transaction);
    return -1;
}

static void builder_append(struct builder *builder, const char *text) {
    size_t length = strlen(text); char *resized; size_t capacity;
    if (builder->failed) return;
    if (builder->used + length + 1U > builder->capacity) {
        capacity = builder->capacity == 0U ? 1024U : builder->capacity;
        while (capacity < builder->used + length + 1U) capacity *= 2U;
        if (capacity > MAX_STORE_BYTES + 4096U) { builder->failed = 1; return; }
        resized = (char *)realloc(builder->data, capacity); if (resized == NULL) { builder->failed = 1; return; }
        builder->data = resized; builder->capacity = capacity;
    }
    memcpy(builder->data + builder->used, text, length); builder->used += length; builder->data[builder->used] = '\0';
}

static void builder_string(struct builder *builder, const char *value) {
    static const char hex[] = "0123456789abcdef"; const unsigned char *cursor = (const unsigned char *)value; char escaped[7];
    builder_append(builder, "\"");
    while (*cursor != '\0') {
        if (*cursor == '"' || *cursor == '\\') { escaped[0] = '\\'; escaped[1] = (char)*cursor; escaped[2] = '\0'; builder_append(builder, escaped); }
        else if (*cursor < 0x20U) { (void)snprintf(escaped, sizeof(escaped), "\\u00%c%c", hex[*cursor >> 4], hex[*cursor & 15U]); builder_append(builder, escaped); }
        else { escaped[0] = (char)*cursor; escaped[1] = '\0'; builder_append(builder, escaped); }
        ++cursor;
    }
    builder_append(builder, "\"");
}

static char *serialize_document(const struct token_document *document, size_t *length) {
    struct builder builder = {NULL, 0U, 0U, 0}; char number[32]; unsigned int index, outlet;
    builder_append(&builder, "{\"generation\":"); (void)snprintf(number, sizeof(number), "%llu", (unsigned long long)document->generation); builder_append(&builder, number); builder_append(&builder, ",\"schemaVersion\":1,\"tokens\":[");
    for (index = 0U; index < document->count; ++index) {
        const struct token_record *record = &document->records[index]; if (index > 0U) builder_append(&builder, ",");
        builder_append(&builder, "{\"createdAt\":"); builder_string(&builder, record->created); builder_append(&builder, ",\"digest\":"); builder_string(&builder, record->digest); builder_append(&builder, record->enabled ? ",\"enabled\":true,\"id\":" : ",\"enabled\":false,\"id\":"); builder_string(&builder, record->id); builder_append(&builder, ",\"label\":"); builder_string(&builder, record->label); builder_append(&builder, ",\"outlets\":");
        if (record->unrestricted) builder_append(&builder, "null"); else { builder_append(&builder, "["); for (outlet = 0U; outlet < record->outlet_count; ++outlet) { if (outlet > 0U) builder_append(&builder, ","); builder_string(&builder, record->outlets[outlet]); } builder_append(&builder, "]"); }
        builder_append(&builder, ",\"scope\":"); builder_string(&builder, record->scope); builder_append(&builder, "}");
    }
    builder_append(&builder, "]}\n");
    if (builder.failed || builder.used > MAX_STORE_BYTES) { free(builder.data); return NULL; }
    *length = builder.used; return builder.data;
}

static int secure_random(unsigned char *output, size_t length) {
    int descriptor; struct stat metadata; size_t used = 0U;
    descriptor = open("/dev/urandom", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISCHR(metadata.st_mode)) { if (descriptor >= 0) (void)close(descriptor); return -1; }
    while (used < length) { ssize_t amount = read(descriptor, output + used, length - used); if (amount <= 0) { (void)close(descriptor); return -1; } used += (size_t)amount; }
    return close(descriptor);
}

static void base64url(const unsigned char *input, size_t length, char *output) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"; size_t in = 0U, out = 0U;
    while (in + 3U <= length) { uint32_t value = ((uint32_t)input[in] << 16) | ((uint32_t)input[in + 1U] << 8) | input[in + 2U]; output[out++] = alphabet[(value >> 18) & 63U]; output[out++] = alphabet[(value >> 12) & 63U]; output[out++] = alphabet[(value >> 6) & 63U]; output[out++] = alphabet[value & 63U]; in += 3U; }
    if (in < length) { uint32_t value = (uint32_t)input[in] << 16; output[out++] = alphabet[(value >> 18) & 63U]; if (in + 1U < length) { value |= (uint32_t)input[in + 1U] << 8; output[out++] = alphabet[(value >> 12) & 63U]; output[out++] = alphabet[(value >> 6) & 63U]; } else output[out++] = alphabet[(value >> 12) & 63U]; }
    output[out] = '\0';
}

static int testing_fault(const char *point) {
#ifdef PM3000_TESTING
    const char *value = getenv("PM3000_TOKEN_FAULT"); return value != NULL && strcmp(value, point) == 0;
#else
    (void)point; return 0;
#endif
}

struct prepared_file { char name[40]; int present; };

static int prepare_bytes(struct transaction *transaction, const unsigned char *bytes,
                         size_t length, int inject_faults, struct prepared_file *prepared) {
    unsigned char random[16]; char encoded[23]; int descriptor = -1; size_t used = 0U; struct stat metadata;
    memset(prepared, 0, sizeof(*prepared));
    if (secure_random(random, sizeof(random)) != 0) return -1;
    base64url(random, sizeof(random), encoded);
    if (snprintf(prepared->name, sizeof(prepared->name), ".tokens.%s", encoded) < 0) return -1;
    descriptor = openat(transaction->directory_fd, prepared->name, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1U || metadata.st_uid != getuid() || (metadata.st_mode & 0777U) != 0600U) goto cleanup;
    prepared->present = 1;
    while (used < length) { ssize_t amount = write(descriptor, bytes + used, length - used); if (amount <= 0) goto cleanup; used += (size_t)amount; }
    if (fsync(descriptor) != 0 || close(descriptor) != 0) { descriptor = -1; goto cleanup; } descriptor = -1;
    if (inject_faults && testing_fault("before_rename")) goto cleanup;
    return 0;
cleanup:
    if (descriptor >= 0) (void)close(descriptor);
    if (prepared->present) { (void)unlinkat(transaction->directory_fd, prepared->name, 0); prepared->present = 0; }
    return -1;
}

static void discard_prepared(struct transaction *transaction, struct prepared_file *prepared) {
    if (prepared->present) { (void)unlinkat(transaction->directory_fd, prepared->name, 0); prepared->present = 0; }
}

/* -1 is pre-commit failure, 0 is durable success, 1 is committed with uncertain durability. */
static int publish_prepared(struct transaction *transaction, struct prepared_file *prepared,
                            int inject_faults) {
    struct stat directory_metadata, current;
    if (fstat(transaction->directory_fd, &directory_metadata) != 0 ||
        fstatat(transaction->parent_directory_fd, transaction->directory_name, &current,
                AT_SYMLINK_NOFOLLOW) != 0 ||
        current.st_dev != directory_metadata.st_dev || current.st_ino != directory_metadata.st_ino)
        return -1;
    if (inject_faults && testing_fault("rename_failure") &&
        unlinkat(transaction->directory_fd, prepared->name, 0) != 0) return -1;
    if (!prepared->present || renameat(transaction->directory_fd, prepared->name,
                                       transaction->directory_fd, transaction->name) != 0) return -1;
    prepared->present = 0;
    if ((inject_faults && testing_fault("after_rename")) || fsync(transaction->directory_fd) != 0) return 1;
    return 0;
}

static int commit_document(struct transaction *transaction) {
    char *serialized; size_t length; int result; struct prepared_file prepared;
    serialized = serialize_document(&transaction->document, &length); if (serialized == NULL) return -1;
    if (prepare_bytes(transaction, (const unsigned char *)serialized, length, 1, &prepared) != 0) { free(serialized); return -1; }
    result = publish_prepared(transaction, &prepared, 1);
    discard_prepared(transaction, &prepared);
    free(serialized); return result;
}

static void skip_space(struct cursor *cursor) { while (cursor->offset < cursor->length && (cursor->data[cursor->offset] == ' ' || cursor->data[cursor->offset] == '\t' || cursor->data[cursor->offset] == '\r' || cursor->data[cursor->offset] == '\n')) ++cursor->offset; }

static int body_expect(struct cursor *cursor, unsigned char value) { skip_space(cursor); if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != value) return -1; return 0; }

static int compare_outlet(const void *left, const void *right) { return strcmp((const char *)left, (const char *)right); }

static int parse_create_request(const unsigned char *body, size_t length, struct create_request *request) {
    struct cursor cursor = {body, length, 0U}; int first = 1;
    memset(request, 0, sizeof(*request)); if (length == 0U || length > BODY_LIMIT || body_expect(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[16]; skip_space(&cursor); if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') { ++cursor.offset; break; }
        if (!first && body_expect(&cursor, ',') != 0) return -1;
        first = 0;
        skip_space(&cursor);
        if (parse_string(&cursor, key, sizeof(key)) != 0 || body_expect(&cursor, ':') != 0) return -1;
        skip_space(&cursor);
        if (strcmp(key, "label") == 0) { if (request->have_label || parse_string(&cursor, request->label, sizeof(request->label)) != 0) return -1; request->have_label = 1; }
        else if (strcmp(key, "scope") == 0) { if (request->have_scope || parse_string(&cursor, request->scope, sizeof(request->scope)) != 0) return -1; request->have_scope = 1; }
        else if (strcmp(key, "outlets") == 0) {
            if (request->have_outlets || body_expect(&cursor, '[') != 0) return -1;
            request->have_outlets = 1;
            skip_space(&cursor);
            while (cursor.offset < cursor.length && cursor.data[cursor.offset] != ']') {
                if (request->outlet_count > 0U && body_expect(&cursor, ',') != 0) return -1;
                skip_space(&cursor);
                if (request->outlet_count >= MAX_OUTLETS || parse_string(&cursor, request->outlets[request->outlet_count], 23U) != 0 || !opaque_id(request->outlets[request->outlet_count])) return -1;
                ++request->outlet_count; skip_space(&cursor);
            }
            if (body_expect(&cursor, ']') != 0) return -1;
        } else return -1;
    }
    skip_space(&cursor);
    if (cursor.offset != cursor.length || !request->have_label || !request->have_scope || !valid_label(request->label) || !valid_scope(request->scope)) return -1;
    if (request->have_outlets) { unsigned int index; qsort(request->outlets, request->outlet_count, 23U, compare_outlet); for (index = 1U; index < request->outlet_count; ++index) if (strcmp(request->outlets[index - 1U], request->outlets[index]) == 0) return -1; }
    return 0;
}

static char *metadata_response(const struct token_document *document) {
    struct builder builder = {NULL, 0U, 0U, 0}; unsigned int index, outlet;
    builder_append(&builder, "{\"tokens\":[");
    for (index = 0U; index < document->count; ++index) { const struct token_record *record = &document->records[index]; if (index > 0U) builder_append(&builder, ","); builder_append(&builder, "{\"id\":"); builder_string(&builder, record->id); builder_append(&builder, ",\"label\":"); builder_string(&builder, record->label); builder_append(&builder, ",\"createdAt\":"); builder_string(&builder, record->created); builder_append(&builder, record->enabled ? ",\"enabled\":true,\"scope\":" : ",\"enabled\":false,\"scope\":"); builder_string(&builder, record->scope); builder_append(&builder, ",\"outlets\":"); if (record->unrestricted) builder_append(&builder, "null"); else { builder_append(&builder, "["); for (outlet = 0U; outlet < record->outlet_count; ++outlet) { if (outlet > 0U) builder_append(&builder, ","); builder_string(&builder, record->outlets[outlet]); } builder_append(&builder, "]"); } builder_append(&builder, "}"); }
    builder_append(&builder, "]}\n"); if (builder.failed) { free(builder.data); return NULL; } return builder.data;
}

pm3000_token_result pm3000_token_list(const char *store_path, const char *administrator, char **response) {
    struct transaction transaction; pm3000_token_result result = PM3000_TOKEN_STORE_ERROR; *response = NULL;
    if (begin_transaction(store_path, &transaction) != 0) return result;
    if (administrator_index(&transaction.document, administrator) < 0) result = PM3000_TOKEN_AUTH;
    else { *response = metadata_response(&transaction.document); if (*response != NULL) result = PM3000_TOKEN_OK; }
    close_transaction(&transaction); return result;
}

pm3000_token_result pm3000_token_create(const char *store_path, const char *administrator,
                                         const unsigned char *body, size_t body_length,
                                         pm3000_token_delivery deliver, void *context) {
    struct create_request request; struct transaction transaction; struct token_record *record; unsigned char random[48]; char token_part[44]; unsigned int attempt, index; pm3000_token_result result = PM3000_TOKEN_STORE_ERROR; struct builder output = {NULL, 0U, 0U, 0}; time_t now; struct tm timestamp; char *serialized = NULL; size_t serialized_length = 0U; struct prepared_file prepared; int publication;
    if (deliver == NULL || parse_create_request(body, body_length, &request) != 0) return PM3000_TOKEN_BAD_REQUEST;
    if (begin_transaction(store_path, &transaction) != 0) return result;
    if (administrator_index(&transaction.document, administrator) < 0) { result = PM3000_TOKEN_AUTH; goto done; }
    if (transaction.document.count >= MAX_TOKENS) { result = PM3000_TOKEN_LIMIT; goto done; }
    if (transaction.document.generation >= INT64_MAX) goto done;
    record = &transaction.document.records[transaction.document.count]; memset(record, 0, sizeof(*record));
    for (attempt = 0U; attempt < 16U; ++attempt) {
        int collision = 0; if (secure_random(random, sizeof(random)) != 0) goto done;
        base64url(random, 32U, token_part); strcpy(record->id, "tok_"); base64url(random + 32U, 16U, record->id + 4); { char plaintext[48]; strcpy(plaintext, "pm3_"); strcat(plaintext, token_part); digest_plaintext(plaintext, record->digest); }
        for (index = 0U; index < transaction.document.count; ++index) if (strcmp(record->id, transaction.document.records[index].id) == 0 || strcmp(record->digest, transaction.document.records[index].digest) == 0) collision = 1;
        if (!collision) break;
    }
    if (attempt == 16U) goto done;
    now = time(NULL); if (now == (time_t)-1 || gmtime_r(&now, &timestamp) == NULL || strftime(record->created, sizeof(record->created), "%Y-%m-%dT%H:%M:%SZ", &timestamp) != 20U) goto done;
    strcpy(record->label, request.label); strcpy(record->scope, request.scope); record->enabled = 1; record->unrestricted = !request.have_outlets; record->outlet_count = request.outlet_count;
    if (request.have_outlets) { record->outlets = (char (*)[23])calloc(MAX_OUTLETS, 23U); if (record->outlets == NULL) goto done; memcpy(record->outlets, request.outlets, (size_t)request.outlet_count * 23U); }
    ++transaction.document.count; ++transaction.document.generation;
    builder_append(&output, "{\"id\":"); builder_string(&output, record->id); builder_append(&output, ",\"label\":"); builder_string(&output, record->label); builder_append(&output, ",\"createdAt\":"); builder_string(&output, record->created); builder_append(&output, ",\"enabled\":true,\"scope\":"); builder_string(&output, record->scope); builder_append(&output, ",\"outlets\":");
    if (record->unrestricted) builder_append(&output, "null"); else { builder_append(&output, "["); for (index = 0U; index < record->outlet_count; ++index) { if (index > 0U) builder_append(&output, ","); builder_string(&output, record->outlets[index]); } builder_append(&output, "]"); }
    builder_append(&output, ",\"token\":\"pm3_"); builder_append(&output, token_part); builder_append(&output, "\"}\n");
    if (output.failed) goto done;
    serialized = serialize_document(&transaction.document, &serialized_length);
    if (serialized == NULL || prepare_bytes(&transaction, (const unsigned char *)serialized,
                                             serialized_length, 1, &prepared) != 0) goto done;
    if (deliver(output.data, context) != 0) {
        discard_prepared(&transaction, &prepared);
        result = PM3000_TOKEN_DELIVERY_ERROR;
        goto done;
    }
    publication = publish_prepared(&transaction, &prepared, 1);
    discard_prepared(&transaction, &prepared);
    if (publication < 0) result = PM3000_TOKEN_RESPONSE_SENT_ERROR;
    else if (publication > 0) result = PM3000_TOKEN_COMMITTED_UNCERTAIN;
    else result = PM3000_TOKEN_OK;
done:
    free(serialized); free(output.data); close_transaction(&transaction); return result;
}

pm3000_token_result pm3000_token_set_enabled(const char *store_path, const char *administrator, const char *token_id_value, int enabled) {
    struct transaction transaction; unsigned int index, enabled_admins = 0U; pm3000_token_result result = PM3000_TOKEN_STORE_ERROR;
    if (!valid_token_id(token_id_value) || (enabled != 0 && enabled != 1)) return PM3000_TOKEN_NOT_FOUND;
    if (begin_transaction(store_path, &transaction) != 0) return result;
    if (administrator_index(&transaction.document, administrator) < 0) { result = PM3000_TOKEN_AUTH; goto done; }
    for (index = 0U; index < transaction.document.count; ++index) if (transaction.document.records[index].enabled && strcmp(transaction.document.records[index].scope, "admin") == 0) ++enabled_admins;
    for (index = 0U; index < transaction.document.count; ++index) if (strcmp(transaction.document.records[index].id, token_id_value) == 0) break;
    if (index == transaction.document.count) { result = PM3000_TOKEN_NOT_FOUND; goto done; }
    if (!enabled && transaction.document.records[index].enabled && strcmp(transaction.document.records[index].scope, "admin") == 0 && enabled_admins == 1U) { result = PM3000_TOKEN_LAST_ADMIN; goto done; }
    if (transaction.document.generation >= INT64_MAX) goto done;
    transaction.document.records[index].enabled = enabled; ++transaction.document.generation;
    { int commit = commit_document(&transaction); if (commit == 0) result = PM3000_TOKEN_OK; else if (commit > 0) result = PM3000_TOKEN_COMMITTED_UNCERTAIN; }
done:
    close_transaction(&transaction); return result;
}

pm3000_token_result pm3000_token_revoke(const char *store_path, const char *administrator, const char *token_id_value) {
    struct transaction transaction; unsigned int index, enabled_admins = 0U; pm3000_token_result result = PM3000_TOKEN_STORE_ERROR;
    if (!valid_token_id(token_id_value)) return PM3000_TOKEN_NOT_FOUND;
    if (begin_transaction(store_path, &transaction) != 0) return result;
    if (administrator_index(&transaction.document, administrator) < 0) { result = PM3000_TOKEN_AUTH; goto done; }
    for (index = 0U; index < transaction.document.count; ++index) if (transaction.document.records[index].enabled && strcmp(transaction.document.records[index].scope, "admin") == 0) ++enabled_admins;
    for (index = 0U; index < transaction.document.count; ++index) if (strcmp(transaction.document.records[index].id, token_id_value) == 0) break;
    if (index == transaction.document.count) { result = PM3000_TOKEN_NOT_FOUND; goto done; }
    if (transaction.document.records[index].enabled && strcmp(transaction.document.records[index].scope, "admin") == 0 && enabled_admins == 1U) { result = PM3000_TOKEN_LAST_ADMIN; goto done; }
    if (transaction.document.generation >= INT64_MAX) goto done;
    free(transaction.document.records[index].outlets);
    if (index + 1U < transaction.document.count) memmove(&transaction.document.records[index], &transaction.document.records[index + 1U], (size_t)(transaction.document.count - index - 1U) * sizeof(transaction.document.records[0]));
    --transaction.document.count; memset(&transaction.document.records[transaction.document.count], 0, sizeof(transaction.document.records[0])); ++transaction.document.generation;
    { int commit = commit_document(&transaction); if (commit == 0) result = PM3000_TOKEN_OK; else if (commit > 0) result = PM3000_TOKEN_COMMITTED_UNCERTAIN; }
done:
    close_transaction(&transaction); return result;
}
