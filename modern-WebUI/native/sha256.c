#include "sha256.h"

#include <string.h>

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32U - (n))))

static const uint32_t constants[64] = {
    0x428a2f98U, 0x71374491U, 0xb5c0fbcfU, 0xe9b5dba5U,
    0x3956c25bU, 0x59f111f1U, 0x923f82a4U, 0xab1c5ed5U,
    0xd807aa98U, 0x12835b01U, 0x243185beU, 0x550c7dc3U,
    0x72be5d74U, 0x80deb1feU, 0x9bdc06a7U, 0xc19bf174U,
    0xe49b69c1U, 0xefbe4786U, 0x0fc19dc6U, 0x240ca1ccU,
    0x2de92c6fU, 0x4a7484aaU, 0x5cb0a9dcU, 0x76f988daU,
    0x983e5152U, 0xa831c66dU, 0xb00327c8U, 0xbf597fc7U,
    0xc6e00bf3U, 0xd5a79147U, 0x06ca6351U, 0x14292967U,
    0x27b70a85U, 0x2e1b2138U, 0x4d2c6dfcU, 0x53380d13U,
    0x650a7354U, 0x766a0abbU, 0x81c2c92eU, 0x92722c85U,
    0xa2bfe8a1U, 0xa81a664bU, 0xc24b8b70U, 0xc76c51a3U,
    0xd192e819U, 0xd6990624U, 0xf40e3585U, 0x106aa070U,
    0x19a4c116U, 0x1e376c08U, 0x2748774cU, 0x34b0bcb5U,
    0x391c0cb3U, 0x4ed8aa4aU, 0x5b9cca4fU, 0x682e6ff3U,
    0x748f82eeU, 0x78a5636fU, 0x84c87814U, 0x8cc70208U,
    0x90befffaU, 0xa4506cebU, 0xbef9a3f7U, 0xc67178f2U
};

static uint32_t read_be32(const unsigned char *value) {
    return ((uint32_t)value[0] << 24) | ((uint32_t)value[1] << 16) |
           ((uint32_t)value[2] << 8) | (uint32_t)value[3];
}

static void write_be32(unsigned char *target, uint32_t value) {
    target[0] = (unsigned char)(value >> 24);
    target[1] = (unsigned char)(value >> 16);
    target[2] = (unsigned char)(value >> 8);
    target[3] = (unsigned char)value;
}

static void transform(sha256_context *context, const unsigned char block[64]) {
    uint32_t words[64];
    uint32_t a, b, c, d, e, f, g, h;
    size_t index;
    for (index = 0; index < 16; ++index) {
        words[index] = read_be32(block + index * 4);
    }
    for (index = 16; index < 64; ++index) {
        uint32_t s0 = ROTR(words[index - 15], 7) ^ ROTR(words[index - 15], 18) ^ (words[index - 15] >> 3);
        uint32_t s1 = ROTR(words[index - 2], 17) ^ ROTR(words[index - 2], 19) ^ (words[index - 2] >> 10);
        words[index] = words[index - 16] + s0 + words[index - 7] + s1;
    }
    a = context->state[0]; b = context->state[1]; c = context->state[2]; d = context->state[3];
    e = context->state[4]; f = context->state[5]; g = context->state[6]; h = context->state[7];
    for (index = 0; index < 64; ++index) {
        uint32_t sum1 = ROTR(e, 6) ^ ROTR(e, 11) ^ ROTR(e, 25);
        uint32_t choice = (e & f) ^ ((~e) & g);
        uint32_t temporary1 = h + sum1 + choice + constants[index] + words[index];
        uint32_t sum0 = ROTR(a, 2) ^ ROTR(a, 13) ^ ROTR(a, 22);
        uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
        uint32_t temporary2 = sum0 + majority;
        h = g; g = f; f = e; e = d + temporary1;
        d = c; c = b; b = a; a = temporary1 + temporary2;
    }
    context->state[0] += a; context->state[1] += b; context->state[2] += c; context->state[3] += d;
    context->state[4] += e; context->state[5] += f; context->state[6] += g; context->state[7] += h;
}

void sha256_init(sha256_context *context) {
    static const uint32_t initial[8] = {
        0x6a09e667U, 0xbb67ae85U, 0x3c6ef372U, 0xa54ff53aU,
        0x510e527fU, 0x9b05688cU, 0x1f83d9abU, 0x5be0cd19U
    };
    memcpy(context->state, initial, sizeof(initial));
    context->bit_count = 0;
    context->block_length = 0;
}

void sha256_update(sha256_context *context, const void *data, size_t length) {
    const unsigned char *input = (const unsigned char *)data;
    context->bit_count += (uint64_t)length * 8U;
    while (length > 0) {
        size_t available = 64U - context->block_length;
        size_t amount = length < available ? length : available;
        memcpy(context->block + context->block_length, input, amount);
        context->block_length += amount;
        input += amount;
        length -= amount;
        if (context->block_length == 64U) {
            transform(context, context->block);
            context->block_length = 0;
        }
    }
}

void sha256_final(sha256_context *context, unsigned char digest[32]) {
    size_t index;
    uint64_t bits = context->bit_count;
    context->block[context->block_length++] = 0x80U;
    if (context->block_length > 56U) {
        memset(context->block + context->block_length, 0, 64U - context->block_length);
        transform(context, context->block);
        context->block_length = 0;
    }
    memset(context->block + context->block_length, 0, 56U - context->block_length);
    for (index = 0; index < 8; ++index) {
        context->block[63U - index] = (unsigned char)(bits >> (index * 8U));
    }
    transform(context, context->block);
    for (index = 0; index < 8; ++index) {
        write_be32(digest + index * 4U, context->state[index]);
    }
    memset(context, 0, sizeof(*context));
}

void sha256_bytes(const void *data, size_t length, unsigned char digest[32]) {
    sha256_context context;
    sha256_init(&context);
    sha256_update(&context, data, length);
    sha256_final(&context, digest);
}
