#include "pm3000_acme_certificate.h"
#include "pm3000_acme_crypto.h"

#include <stdio.h>

int main(void)
{
    struct pm3000_acme_key server_key = {0};
    struct pm3000_acme_key wrong_key = {0};
    static const char *valid_names[] = {"acme.example.test", "localhost"};
    static const char *partial_names[] = {"acme.example.test"};
    static const char *invalid_names[] = {"other.example.test"};
    if (pm3000_acme_crypto_key_load(
            "tests/fixtures/tls/server-key.pem", &server_key) !=
            PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_load(
            "tests/fixtures/account-test-key.pem", &wrong_key) !=
            PM3000_ACME_CRYPTO_OK) return 2;
    if (pm3000_acme_certificate_validate(
            "tests/fixtures/tls/issued.pem", "tests/fixtures/tls/ca.pem",
            &server_key, valid_names, 2U) != PM3000_ACME_CERTIFICATE_OK ||
        pm3000_acme_certificate_validate(
            "tests/fixtures/tls/issued.pem", "tests/fixtures/tls/ca.pem",
            &server_key, partial_names, 1U) == PM3000_ACME_CERTIFICATE_OK ||
        pm3000_acme_certificate_validate(
            "tests/fixtures/tls/issued.pem", "tests/fixtures/tls/ca.pem",
            &server_key, invalid_names, 1U) == PM3000_ACME_CERTIFICATE_OK ||
        pm3000_acme_certificate_validate(
            "tests/fixtures/tls/issued.pem", "tests/fixtures/tls/ca.pem",
            &wrong_key, valid_names, 2U) == PM3000_ACME_CERTIFICATE_OK) {
        fprintf(stderr, "certificate validation contract failed\n");
        pm3000_acme_crypto_key_free(&wrong_key);
        pm3000_acme_crypto_key_free(&server_key);
        return 1;
    }
    pm3000_acme_crypto_key_free(&wrong_key);
    pm3000_acme_crypto_key_free(&server_key);
    puts("certificate.tests.complete=yes");
    return 0;
}
