#include "identifiers.h"
#include "sha256.h"

#include <stdint.h>
#include <stdlib.h>
#include <string.h>

static const char base64url[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

static void encode_prefix(const unsigned char digest[32], char output[PM3000_ID_LENGTH + 1U]) {
    size_t input = 0;
    size_t written = 0;
    while (written < PM3000_ID_LENGTH) {
        uint32_t value = (uint32_t)digest[input] << 16;
        value |= (uint32_t)digest[input + 1U] << 8;
        value |= digest[input + 2U];
        if (written < PM3000_ID_LENGTH) output[written++] = base64url[(value >> 18) & 63U];
        if (written < PM3000_ID_LENGTH) output[written++] = base64url[(value >> 12) & 63U];
        if (written < PM3000_ID_LENGTH) output[written++] = base64url[(value >> 6) & 63U];
        if (written < PM3000_ID_LENGTH) output[written++] = base64url[value & 63U];
        input += 3U;
    }
    output[PM3000_ID_LENGTH] = '\0';
}

int pm3000_derive_id(const char *kind, const char *identity,
                     char output[PM3000_ID_LENGTH + 1U]) {
    sha256_context context;
    unsigned char digest[32];
    const char *domain;
    size_t domain_length;
    if (strcmp(kind, "outlet") == 0) {
        domain = "pm3000-rest-v1\0outlet\0";
        domain_length = 22U;
    } else if (strcmp(kind, "pdu") == 0) {
        domain = "pm3000-rest-v1\0pdu\0";
        domain_length = 19U;
    } else {
        return -1;
    }
    sha256_init(&context);
    sha256_update(&context, domain, domain_length);
    sha256_update(&context, identity, strlen(identity));
    sha256_final(&context, digest);
    encode_prefix(digest, output);
    return 0;
}

static int compare_strings(const void *left, const void *right) {
    const unsigned char *a = (const unsigned char *)*(const char *const *)left;
    const unsigned char *b = (const unsigned char *)*(const char *const *)right;
    while (*a != 0U && *a == *b) { ++a; ++b; }
    return (int)*a - (int)*b;
}

int pm3000_inventory_revision(char **identities, size_t count,
                              char output[PM3000_ID_LENGTH + 1U]) {
    static const char domain[] = "pm3000-rest-v1\0inventory\0";
    sha256_context context;
    unsigned char digest[32];
    size_t index;
    qsort(identities, count, sizeof(*identities), compare_strings);
    sha256_init(&context);
    sha256_update(&context, domain, 25U);
    for (index = 0; index < count; ++index) {
        size_t length = strlen(identities[index]);
        unsigned char encoded[4];
        if (length > UINT32_MAX) return -1;
        encoded[0] = (unsigned char)(length >> 24);
        encoded[1] = (unsigned char)(length >> 16);
        encoded[2] = (unsigned char)(length >> 8);
        encoded[3] = (unsigned char)length;
        sha256_update(&context, encoded, sizeof(encoded));
        sha256_update(&context, identities[index], length);
    }
    sha256_final(&context, digest);
    encode_prefix(digest, output);
    return 0;
}
