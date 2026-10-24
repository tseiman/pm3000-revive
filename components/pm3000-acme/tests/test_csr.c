#include "pm3000_acme_crypto.h"

#include <stdio.h>

int main(void)
{
    static const char *names[] = {
        "PDU1.TSEI.MDN",
        "usv3.tsei.mdn",
        "usv3-24v.tsei.mdn"
    };
    struct pm3000_acme_key key = { 0 };
    unsigned char der[PM3000_ACME_CSR_DER_MAX];
    unsigned int der_length = 0U;
    FILE *output;
    int failed = 0;

    if (pm3000_acme_crypto_key_load("tests/fixtures/account-test-key.pem",
                                    &key) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_csr_der(&key, names, 3U, der, sizeof(der),
                                   &der_length) != PM3000_ACME_CRYPTO_OK ||
        der_length < 256U || der[0] != 0x30U) {
        fprintf(stderr, "CSR generation failed\n");
        failed = 1;
    } else {
        output = fopen("build/test-request.csr.der", "wb");
        if (output == NULL || fwrite(der, 1U, der_length, output) != der_length ||
            fclose(output) != 0) {
            fprintf(stderr, "CSR fixture write failed\n");
            if (output != NULL) fclose(output);
            failed = 1;
        }
    }

    if (pm3000_acme_crypto_csr_der(&key, names, 0U, der, sizeof(der),
                                   &der_length) == PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_csr_der(&key, names, 3U, der, 32U,
                                   &der_length) == PM3000_ACME_CRYPTO_OK) {
        fprintf(stderr, "CSR bounds contract failed\n");
        failed = 1;
    }

    pm3000_acme_crypto_key_free(&key);
    if (failed) return 1;
    puts("csr.tests.complete=yes");
    return 0;
}
