#include "pm3000_acme_jws.h"
#include "pm3000_acme_base64url.h"
#include "pm3000_acme_url.h"

static int append_char(char *output, unsigned int capacity,
                       unsigned int *used, char value)
{
    if (*used + 1U >= capacity) return 0;
    output[(*used)++] = value;
    output[*used] = '\0';
    return 1;
}

static int append_text(char *output, unsigned int capacity,
                       unsigned int *used, const char *text)
{
    unsigned int index = 0U;
    while (text[index] != '\0') {
        if (!append_char(output, capacity, used, text[index++])) return 0;
    }
    return 1;
}

static int append_json_string(char *output, unsigned int capacity,
                              unsigned int *used, const char *text)
{
    unsigned int index = 0U;
    if (!append_char(output, capacity, used, '"')) return 0;
    while (text[index] != '\0') {
        unsigned char value = (unsigned char)text[index++];
        if (value < 0x20U || value > 0x7eU) return 0;
        if ((value == '"' || value == '\\') &&
            !append_char(output, capacity, used, '\\')) return 0;
        if (!append_char(output, capacity, used, (char)value)) return 0;
    }
    return append_char(output, capacity, used, '"');
}

static int nonce_valid(const char *nonce)
{
    unsigned int length = 0U;
    if (nonce == (const char *)0) return 0;
    while (nonce[length] != '\0') {
        char value = nonce[length];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_')) {
            return 0;
        }
        if (++length > PM3000_ACME_NONCE_MAX) return 0;
    }
    return length != 0U;
}

int pm3000_acme_jws_create(const struct pm3000_acme_key *key,
                           const char *nonce, const char *url,
                           const char *account_kid,
                           const unsigned char *payload,
                           unsigned int payload_length,
                           char *output, unsigned int output_capacity)
{
    struct pm3000_acme_url request_url;
    struct pm3000_acme_url kid_url;
    char jwk[PM3000_ACME_JWK_MAX];
    char protected_json[PM3000_ACME_JWS_PROTECTED_MAX];
    char protected_b64[PM3000_ACME_JWS_PROTECTED_MAX * 2U];
    char payload_b64[PM3000_ACME_JWS_PAYLOAD_B64_MAX];
    char signature_b64[PM3000_ACME_RSA_SIGNATURE_MAX * 2U];
    unsigned char signing_input[PM3000_ACME_JWS_MAX];
    unsigned char signature[PM3000_ACME_RSA_SIGNATURE_MAX];
    unsigned int protected_used = 0U;
    unsigned int signing_length;
    unsigned int signature_length;
    unsigned int output_used = 0U;
    unsigned int index;
    int crypto_result;

    if (output == (char *)0 || output_capacity == 0U)
        return PM3000_ACME_JWS_INVALID;
    output[0] = '\0';
    if (key == (const struct pm3000_acme_key *)0 ||
        !nonce_valid(nonce) || url == (const char *)0 ||
        (payload == (const unsigned char *)0 && payload_length != 0U) ||
        payload_length > PM3000_ACME_JWS_PAYLOAD_MAX ||
        pm3000_acme_url_parse(url, &request_url) != PM3000_ACME_URL_OK) {
        return PM3000_ACME_JWS_INVALID;
    }
    if (account_kid != (const char *)0 &&
        (pm3000_acme_url_parse(account_kid, &kid_url) != PM3000_ACME_URL_OK ||
         !pm3000_acme_url_same_origin(&request_url, &kid_url))) {
        return PM3000_ACME_JWS_INVALID;
    }

    protected_json[0] = '\0';
    if (!append_text(protected_json, sizeof(protected_json), &protected_used,
                     "{\"alg\":\"RS256\",")) goto limit;
    if (account_kid == (const char *)0) {
        if (pm3000_acme_crypto_account_jwk(key, jwk, sizeof(jwk)) !=
                PM3000_ACME_CRYPTO_OK ||
            !append_text(protected_json, sizeof(protected_json), &protected_used,
                         "\"jwk\":") ||
            !append_text(protected_json, sizeof(protected_json), &protected_used,
                         jwk)) goto crypto;
    } else {
        if (!append_text(protected_json, sizeof(protected_json), &protected_used,
                         "\"kid\":") ||
            !append_json_string(protected_json, sizeof(protected_json),
                                &protected_used, account_kid)) goto limit;
    }
    if (!append_text(protected_json, sizeof(protected_json), &protected_used,
                     ",\"nonce\":") ||
        !append_json_string(protected_json, sizeof(protected_json),
                            &protected_used, nonce) ||
        !append_text(protected_json, sizeof(protected_json), &protected_used,
                     ",\"url\":") ||
        !append_json_string(protected_json, sizeof(protected_json),
                            &protected_used, url) ||
        !append_char(protected_json, sizeof(protected_json), &protected_used,
                     '}')) goto limit;

    if (pm3000_acme_base64url_encode(
            (const unsigned char *)protected_json, protected_used,
            protected_b64, sizeof(protected_b64)) != PM3000_ACME_BASE64URL_OK ||
        pm3000_acme_base64url_encode(payload, payload_length, payload_b64,
                                     sizeof(payload_b64)) !=
            PM3000_ACME_BASE64URL_OK) goto limit;
    signing_length = 0U;
    for (index = 0U; protected_b64[index] != '\0'; ++index) {
        if (signing_length >= sizeof(signing_input)) goto limit;
        signing_input[signing_length++] = (unsigned char)protected_b64[index];
    }
    if (signing_length >= sizeof(signing_input)) goto limit;
    signing_input[signing_length++] = '.';
    for (index = 0U; payload_b64[index] != '\0'; ++index) {
        if (signing_length >= sizeof(signing_input)) goto limit;
        signing_input[signing_length++] = (unsigned char)payload_b64[index];
    }
    crypto_result = pm3000_acme_crypto_sign_rs256(
        key, signing_input, signing_length, signature, sizeof(signature),
        &signature_length);
    if (crypto_result != PM3000_ACME_CRYPTO_OK) goto crypto;
    if (pm3000_acme_base64url_encode(signature, signature_length,
                                     signature_b64, sizeof(signature_b64)) !=
        PM3000_ACME_BASE64URL_OK) goto limit;

    if (!append_text(output, output_capacity, &output_used, "{\"protected\":\"") ||
        !append_text(output, output_capacity, &output_used, protected_b64) ||
        !append_text(output, output_capacity, &output_used, "\",\"payload\":\"") ||
        !append_text(output, output_capacity, &output_used, payload_b64) ||
        !append_text(output, output_capacity, &output_used, "\",\"signature\":\"") ||
        !append_text(output, output_capacity, &output_used, signature_b64) ||
        !append_text(output, output_capacity, &output_used, "\"}")) goto limit;
    return PM3000_ACME_JWS_OK;

limit:
    output[0] = '\0';
    return PM3000_ACME_JWS_LIMIT;
crypto:
    output[0] = '\0';
    return PM3000_ACME_JWS_CRYPTO;
}
