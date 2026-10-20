#ifndef PM3000_SHA256_H
#define PM3000_SHA256_H

#include <stddef.h>
#include <stdint.h>

typedef struct {
    uint32_t state[8];
    uint64_t bit_count;
    unsigned char block[64];
    size_t block_length;
} sha256_context;

void sha256_init(sha256_context *context);
void sha256_update(sha256_context *context, const void *data, size_t length);
void sha256_final(sha256_context *context, unsigned char digest[32]);
void sha256_bytes(const void *data, size_t length, unsigned char digest[32]);

#endif
