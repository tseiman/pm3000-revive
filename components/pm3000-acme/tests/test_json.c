#include "pm3000_acme_json.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void fail(const char *message)
{
    fprintf(stderr, "%s\n", message);
    ++failures;
}

static void expect_rejected(const unsigned char *json, unsigned int length,
                            const char *label)
{
    struct pm3000_acme_json_document document;
    if (pm3000_acme_json_parse(json, length, &document) == PM3000_ACME_JSON_OK) {
        fprintf(stderr, "expected rejection: %s\n", label);
        ++failures;
    }
}

int main(void)
{
    static const unsigned char valid[] =
        "{\"newNonce\":\"https:\\/\\/acme.example.test\\/nonce\","
        "\"nested\":{\"emoji\":\"\\uD83D\\uDE00\"},"
        "\"items\":[\"a\",true,2,null]}";
    static const unsigned char duplicate[] =
        "{\"newNonce\":\"a\",\"new\\u004Eonce\":\"b\"}";
    static const unsigned char malformed_surrogate[] = "{\"x\":\"\\uD800x\"}";
    static const unsigned char trailing[] = "{} false";
    static const unsigned char bad_number[] = "{\"x\":01}";
    static const unsigned char bad_utf8[] = { '{', '"', 'x', '"', ':', '"',
                                               0xc0U, 0x80U, '"', '}' };
    static const unsigned char too_deep[] = "[[[[[[[[[0]]]]]]]]]";
    struct pm3000_acme_json_document document;
    int nonce;
    int nested;
    int emoji;
    int items;
    int item;
    char text[128];
    char small[2] = { 'x', 'x' };
    unsigned int count;

    if (pm3000_acme_json_parse(valid, sizeof(valid) - 1U, &document) !=
        PM3000_ACME_JSON_OK) {
        fail("valid JSON rejected");
    } else {
        if (pm3000_acme_json_object_get(&document, 0, "newNonce", &nonce) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_json_string_copy(&document, nonce, text, sizeof(text)) !=
                PM3000_ACME_JSON_OK ||
            strcmp(text, "https://acme.example.test/nonce") != 0) {
            fail("escaped URL extraction failed");
        }
        if (pm3000_acme_json_object_get(&document, 0, "nested", &nested) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_json_object_get(&document, nested, "emoji", &emoji) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_json_string_copy(&document, emoji, text, sizeof(text)) !=
                PM3000_ACME_JSON_OK ||
            strcmp(text, "\xF0\x9F\x98\x80") != 0) {
            fail("surrogate-pair extraction failed");
        }
        if (pm3000_acme_json_object_get(&document, 0, "items", &items) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_json_array_length(&document, items, &count) !=
                PM3000_ACME_JSON_OK || count != 4U ||
            pm3000_acme_json_array_get(&document, items, 0U, &item) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_json_string_copy(&document, item, text, sizeof(text)) !=
                PM3000_ACME_JSON_OK || strcmp(text, "a") != 0) {
            fail("array traversal failed");
        }
        if (pm3000_acme_json_string_copy(&document, nonce, small,
                                         sizeof(small)) !=
                PM3000_ACME_JSON_OUTPUT_TOO_SMALL || small[0] != '\0') {
            fail("short string-output contract failed");
        }
        if (pm3000_acme_json_object_get(&document, 0, "absent", &item) !=
                PM3000_ACME_JSON_NOT_FOUND) {
            fail("missing object key contract failed");
        }
    }

    expect_rejected(duplicate, sizeof(duplicate) - 1U, "escaped duplicate key");
    expect_rejected(malformed_surrogate, sizeof(malformed_surrogate) - 1U,
                    "malformed surrogate");
    expect_rejected(trailing, sizeof(trailing) - 1U, "trailing document");
    expect_rejected(bad_number, sizeof(bad_number) - 1U, "leading-zero number");
    expect_rejected(bad_utf8, sizeof(bad_utf8), "overlong UTF-8");
    expect_rejected(too_deep, sizeof(too_deep) - 1U, "excessive nesting");
    expect_rejected(valid, PM3000_ACME_JSON_MAX_BYTES + 1U, "declared oversize");

    if (failures != 0) {
        fprintf(stderr, "json.tests.failed=%d\n", failures);
        return 1;
    }
    puts("json.tests.complete=yes");
    return 0;
}
