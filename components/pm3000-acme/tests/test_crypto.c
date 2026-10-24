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

int main(void)
{
    struct pm3000_acme_key fixture = { 0 };
    struct pm3000_acme_key generated = { 0 };
    struct pm3000_acme_key reloaded = { 0 };
    char jwk[PM3000_ACME_JWK_MAX];
    char thumbprint[PM3000_ACME_THUMBPRINT_MAX];
    int failed = 0;

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
        pm3000_acme_crypto_key_write("build/generated-account-key.pem",
                                    &generated) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_load("build/generated-account-key.pem",
                                    &reloaded) != PM3000_ACME_CRYPTO_OK ||
        exercise_key(&reloaded) != 0) {
        fprintf(stderr, "generated RSA key contract failed\n");
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
