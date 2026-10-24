#include "pm3000_acme_protocol.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_invalid(const char *json, const struct pm3000_acme_url *origin,
                           const char *label)
{
    struct pm3000_acme_directory directory;
    if (pm3000_acme_directory_parse((const unsigned char *)json,
                                    (unsigned int)strlen(json), origin,
                                    &directory) == PM3000_ACME_PROTOCOL_OK) {
        fprintf(stderr, "expected invalid directory: %s\n", label);
        ++failures;
    }
}

int main(void)
{
    static const char valid[] =
        "{\"meta\":{\"termsOfService\":\"https://acme.example.test/tos\"},"
        "\"newOrder\":\"https://acme.example.test/new-order\","
        "\"newNonce\":\"https://ACME.EXAMPLE.TEST/new-nonce\","
        "\"newAccount\":\"https://acme.example.test/new-account\"}";
    struct pm3000_acme_url origin;
    struct pm3000_acme_directory directory;

    if (pm3000_acme_url_parse("https://acme.example.test/directory", &origin) !=
        PM3000_ACME_URL_OK) {
        fprintf(stderr, "origin fixture invalid\n");
        return 1;
    }
    if (pm3000_acme_directory_parse((const unsigned char *)valid,
                                    sizeof(valid) - 1U, &origin,
                                    &directory) != PM3000_ACME_PROTOCOL_OK ||
        strcmp(directory.new_nonce_text,
               "https://ACME.EXAMPLE.TEST/new-nonce") != 0 ||
        strcmp(directory.new_nonce.host, "acme.example.test") != 0 ||
        strcmp(directory.new_order.path, "/new-order") != 0) {
        fprintf(stderr, "valid directory rejected or decoded incorrectly\n");
        ++failures;
    }

    expect_invalid("{\"newNonce\":\"https://acme.example.test/n\","
                   "\"newAccount\":\"https://acme.example.test/a\"}",
                   &origin, "missing newOrder");
    expect_invalid("{\"newNonce\":\"https://other.example.test/n\","
                   "\"newAccount\":\"https://acme.example.test/a\","
                   "\"newOrder\":\"https://acme.example.test/o\"}",
                   &origin, "cross-origin endpoint");
    expect_invalid("{\"newNonce\":\"http://acme.example.test/n\","
                   "\"newAccount\":\"https://acme.example.test/a\","
                   "\"newOrder\":\"https://acme.example.test/o\"}",
                   &origin, "non-HTTPS endpoint");
    expect_invalid("{\"newNonce\":3,"
                   "\"newAccount\":\"https://acme.example.test/a\","
                   "\"newOrder\":\"https://acme.example.test/o\"}",
                   &origin, "wrong endpoint type");

    if (failures != 0) {
        fprintf(stderr, "directory.tests.failed=%d\n", failures);
        return 1;
    }
    puts("directory.tests.complete=yes");
    return 0;
}
