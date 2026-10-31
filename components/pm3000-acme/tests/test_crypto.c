#include "pm3000_acme_crypto.h"

#include <stdio.h>
#include <string.h>

static int exercise_key(struct pm3000_acme_key *key)
{
    static const unsigned char message[] = "protected.payload";
    unsigned char signature[PM3000_ACME_RSA_SIGNATURE_MAX];
    unsigned int signature_length = 0U;
    char jwk[PM3000_ACME_JWK_MAX];
    char thumbprint[PM3000_ACME_THUMBPRINT_MAX];

    if (pm3000_acme_crypto_account_jwk(key, jwk, sizeof(jwk)) !=
            PM3000_ACME_CRYPTO_OK || jwk[0] != '{' ||
        pm3000_acme_crypto_thumbprint(key, thumbprint,
                                     sizeof(thumbprint)) !=
            PM3000_ACME_CRYPTO_OK || thumbprint[0] == '\0' ||
        pm3000_acme_crypto_sign_rs256(key, message, sizeof(message) - 1U,
                                     signature, sizeof(signature),
                                     &signature_length) !=
            PM3000_ACME_CRYPTO_OK || signature_length != 256U ||
        pm3000_acme_crypto_verify_rs256(key, message, sizeof(message) - 1U,
                                       signature, signature_length) !=
            PM3000_ACME_CRYPTO_OK) {
        return -1;
    }
    signature[0] ^= 1U;
    if (pm3000_acme_crypto_verify_rs256(key, message, sizeof(message) - 1U,
                                       signature, signature_length) ==
        PM3000_ACME_CRYPTO_OK) {
        return -1;
    }
    return 0;
}

static int write_bytes(const char *path, const unsigned char *data,
                       unsigned int length)
{
    FILE *file = fopen(path, "wb");
    int result;
    if (file == NULL) return -1;
    result = fwrite(data, 1U, length, file) == length ? 0 : -1;
    if (fclose(file) != 0) result = -1;
    return result;
}

int main(void)
{
    struct pm3000_acme_key fixture = { 0 };
    struct pm3000_acme_key generated = { 0 };
    struct pm3000_acme_key reloaded = { 0 };
    char jwk[PM3000_ACME_JWK_MAX];
    char thumbprint[PM3000_ACME_THUMBPRINT_MAX];
    unsigned char pem[4096U];
    unsigned int pem_length = 0U;
    unsigned char digest[PM3000_ACME_SHA256_BYTES];
    static const unsigned char expected_digest[PM3000_ACME_SHA256_BYTES] = {
        0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea,
        0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23,
        0xb0, 0x03, 0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c,
        0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
    };
    int failed = 0;

    if (pm3000_acme_crypto_sha256((const unsigned char *)"abc", 3U,
                                  digest) != PM3000_ACME_CRYPTO_OK ||
        memcmp(digest, expected_digest, sizeof(digest)) != 0) {
        fprintf(stderr, "SHA-256 bytes contract failed\n");
        failed = 1;
    }

    if (pm3000_acme_crypto_key_load("tests/fixtures/account-test-key.pem",
                                    &fixture) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_account_jwk(&fixture, jwk, sizeof(jwk)) !=
            PM3000_ACME_CRYPTO_OK ||
        strncmp(jwk, "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"",
                sizeof("{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"") - 1U) != 0 ||
        jwk[strlen(jwk) - 2U] != '\"' || jwk[strlen(jwk) - 1U] != '}' ||
        pm3000_acme_crypto_thumbprint(&fixture, thumbprint,
                                     sizeof(thumbprint)) !=
            PM3000_ACME_CRYPTO_OK || strlen(thumbprint) != 43U ||
        exercise_key(&fixture) != 0) {
        fprintf(stderr, "fixture RSA/JWK/RS256 contract failed\n");
        failed = 1;
    }

    if (pm3000_acme_crypto_key_generate_rsa2048(&generated) !=
            PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_pem(&generated, pem, sizeof(pem),
                                   &pem_length) != PM3000_ACME_CRYPTO_OK ||
        pem_length < 64U || pem_length >= sizeof(pem) ||
        memcmp(pem, "-----BEGIN PRIVATE KEY-----", 27U) != 0) {
        fprintf(stderr, "generated RSA key serialization failed\n");
        failed = 1;
    } else if (write_bytes("build/generated-account-key.pem", pem,
                           pem_length) != 0 ||
               pm3000_acme_crypto_key_load("build/generated-account-key.pem",
                                           &reloaded) !=
                   PM3000_ACME_CRYPTO_OK ||
               exercise_key(&reloaded) != 0) {
        fprintf(stderr, "serialized RSA key reload failed\n");
        failed = 1;
    }

    pm3000_acme_crypto_key_free(&reloaded);
    pm3000_acme_crypto_key_free(&generated);
    pm3000_acme_crypto_key_free(&fixture);
    remove("build/generated-account-key.pem");

    if (failed) return 1;
    puts("crypto.tests.complete=yes");
    return 0;
}
