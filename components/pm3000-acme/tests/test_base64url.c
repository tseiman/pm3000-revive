#include "pm3000_acme_base64url.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_encoding(const unsigned char *input, unsigned int input_length,
                            const char *expected)
{
    char output[64];
    int result = pm3000_acme_base64url_encode(input, input_length,
                                               output, sizeof(output));
    if (result != PM3000_ACME_BASE64URL_OK || strcmp(output, expected) != 0) {
        fprintf(stderr, "base64url encoding mismatch for length %u\n",
                input_length);
        ++failures;
    }
}

int main(void)
{
    static const unsigned char binary[] = { 0xfbU, 0xefU, 0xffU };
    char small[2] = { 'x', 'x' };

    expect_encoding((const unsigned char *)"", 0U, "");
    expect_encoding((const unsigned char *)"f", 1U, "Zg");
    expect_encoding((const unsigned char *)"fo", 2U, "Zm8");
    expect_encoding((const unsigned char *)"foo", 3U, "Zm9v");
    expect_encoding((const unsigned char *)"foob", 4U, "Zm9vYg");
    expect_encoding((const unsigned char *)"fooba", 5U, "Zm9vYmE");
    expect_encoding((const unsigned char *)"foobar", 6U, "Zm9vYmFy");
    expect_encoding(binary, sizeof(binary), "--__");

    if (pm3000_acme_base64url_encode((const unsigned char *)"f", 1U,
                                     small, sizeof(small)) !=
        PM3000_ACME_BASE64URL_OUTPUT_TOO_SMALL || small[0] != '\0') {
        fprintf(stderr, "base64url short-output contract mismatch\n");
        ++failures;
    }
    if (pm3000_acme_base64url_encode((const unsigned char *)0, 1U,
                                     small, sizeof(small)) !=
        PM3000_ACME_BASE64URL_INVALID) {
        fprintf(stderr, "base64url NULL-input contract mismatch\n");
        ++failures;
    }

    if (failures != 0) {
        fprintf(stderr, "base64url.tests.failed=%d\n", failures);
        return 1;
    }
    puts("base64url.tests.complete=yes");
    return 0;
}
