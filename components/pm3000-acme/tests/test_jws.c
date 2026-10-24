#include "pm3000_acme_jws.h"
#include "pm3000_acme_crypto.h"
#include "pm3000_acme_json.h"

#include <stdio.h>
#include <string.h>

static int decode_value(char value)
{
    if (value >= 'A' && value <= 'Z') return value - 'A';
    if (value >= 'a' && value <= 'z') return value - 'a' + 26;
    if (value >= '0' && value <= '9') return value - '0' + 52;
    if (value == '-') return 62;
    if (value == '_') return 63;
    return -1;
}

static int decode(const char *input, unsigned char *output,
                  unsigned int capacity, unsigned int *length)
{
    unsigned int used = 0U;
    unsigned int bits = 0U;
    unsigned int accumulator = 0U;
    unsigned int index;
    for (index = 0U; input[index] != '\0'; ++index) {
        int value = decode_value(input[index]);
        if (value < 0) return -1;
        accumulator = (accumulator << 6) | (unsigned int)value;
        bits += 6U;
        if (bits >= 8U) {
            bits -= 8U;
            if (used >= capacity) return -1;
            output[used++] = (unsigned char)(accumulator >> bits);
            accumulator &= bits == 0U ? 0U : (1U << bits) - 1U;
        }
    }
    if (bits >= 6U || accumulator != 0U) return -1;
    *length = used;
    return 0;
}

static int object_string(const struct pm3000_acme_json_document *document,
                         int object, const char *key, char *output,
                         unsigned int capacity)
{
    int token;
    return pm3000_acme_json_object_get(document, object, key, &token) == 0 &&
           pm3000_acme_json_string_copy(document, token, output, capacity) == 0
               ? 0 : -1;
}

int main(void)
{
    static const unsigned char payload[] =
        "{\"termsOfServiceAgreed\":true}";
    struct pm3000_acme_key key = { 0 };
    struct pm3000_acme_json_document envelope;
    struct pm3000_acme_json_document protected_document;
    char jws[PM3000_ACME_JWS_MAX];
    char protected_text[PM3000_ACME_JWS_PROTECTED_MAX];
    char payload_text[PM3000_ACME_JWS_PAYLOAD_B64_MAX];
    char signature_text[PM3000_ACME_RSA_SIGNATURE_MAX * 2U];
    char value[PM3000_ACME_JWK_MAX];
    unsigned char protected_json[PM3000_ACME_JWS_PROTECTED_MAX];
    unsigned char decoded_payload[256];
    unsigned char signature[PM3000_ACME_RSA_SIGNATURE_MAX];
    unsigned char signing_input[PM3000_ACME_JWS_MAX];
    unsigned int protected_length;
    unsigned int payload_length;
    unsigned int signature_length;
    unsigned int signing_length;
    int failed = 0;

    if (pm3000_acme_crypto_key_load("tests/fixtures/account-test-key.pem",
                                    &key) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_jws_create(
            &key, "nonce_ABC-123", "https://acme.example.test/new-account",
            (const char *)0, payload, sizeof(payload) - 1U,
            jws, sizeof(jws)) != PM3000_ACME_JWS_OK ||
        pm3000_acme_json_parse((const unsigned char *)jws,
                               (unsigned int)strlen(jws), &envelope) != 0 ||
        object_string(&envelope, 0, "protected", protected_text,
                      sizeof(protected_text)) != 0 ||
        object_string(&envelope, 0, "payload", payload_text,
                      sizeof(payload_text)) != 0 ||
        object_string(&envelope, 0, "signature", signature_text,
                      sizeof(signature_text)) != 0 ||
        decode(protected_text, protected_json, sizeof(protected_json),
               &protected_length) != 0 ||
        pm3000_acme_json_parse(protected_json, protected_length,
                               &protected_document) != 0 ||
        object_string(&protected_document, 0, "alg", value,
                      sizeof(value)) != 0 || strcmp(value, "RS256") != 0 ||
        object_string(&protected_document, 0, "nonce", value,
                      sizeof(value)) != 0 || strcmp(value, "nonce_ABC-123") != 0 ||
        object_string(&protected_document, 0, "url", value,
                      sizeof(value)) != 0 ||
        strcmp(value, "https://acme.example.test/new-account") != 0 ||
        pm3000_acme_json_object_get(&protected_document, 0, "jwk",
                                    (int *)&signing_length) != 0 ||
        decode(payload_text, decoded_payload, sizeof(decoded_payload),
               &payload_length) != 0 || payload_length != sizeof(payload) - 1U ||
        memcmp(decoded_payload, payload, payload_length) != 0 ||
        decode(signature_text, signature, sizeof(signature),
               &signature_length) != 0) {
        fprintf(stderr, "new-account JWS structure failed\n");
        failed = 1;
    } else {
        signing_length = (unsigned int)strlen(protected_text);
        memcpy(signing_input, protected_text, signing_length++);
        signing_input[signing_length - 1U] = '.';
        memcpy(signing_input + signing_length, payload_text,
               strlen(payload_text));
        signing_length += (unsigned int)strlen(payload_text);
        if (pm3000_acme_crypto_verify_rs256(
                &key, signing_input, signing_length, signature,
                signature_length) != PM3000_ACME_CRYPTO_OK) {
            fprintf(stderr, "JWS signature verification failed\n");
            failed = 1;
        }
    }

    if (pm3000_acme_jws_create(
            &key, "nextNonce", "https://acme.example.test/order/1",
            "https://acme.example.test/account/7",
            (const unsigned char *)"", 0U, jws, sizeof(jws)) !=
            PM3000_ACME_JWS_OK ||
        pm3000_acme_json_parse((const unsigned char *)jws,
                               (unsigned int)strlen(jws), &envelope) != 0 ||
        object_string(&envelope, 0, "payload", payload_text,
                      sizeof(payload_text)) != 0 || payload_text[0] != '\0' ||
        object_string(&envelope, 0, "protected", protected_text,
                      sizeof(protected_text)) != 0 ||
        decode(protected_text, protected_json, sizeof(protected_json),
               &protected_length) != 0 ||
        pm3000_acme_json_parse(protected_json, protected_length,
                               &protected_document) != 0 ||
        object_string(&protected_document, 0, "kid", value,
                      sizeof(value)) != 0 ||
        strcmp(value, "https://acme.example.test/account/7") != 0 ||
        pm3000_acme_json_object_get(&protected_document, 0, "jwk",
                                    (int *)&signing_length) !=
            PM3000_ACME_JSON_NOT_FOUND) {
        fprintf(stderr, "account-kid POST-as-GET JWS structure failed\n");
        failed = 1;
    }

    if (pm3000_acme_jws_create(
            &key, "bad nonce", "https://acme.example.test/order/1",
            "https://acme.example.test/account/7", payload,
            sizeof(payload) - 1U, jws, sizeof(jws)) == PM3000_ACME_JWS_OK) {
        fprintf(stderr, "invalid nonce accepted\n");
        failed = 1;
    }

    pm3000_acme_crypto_key_free(&key);
    if (failed) return 1;
    puts("jws.tests.complete=yes");
    return 0;
}
