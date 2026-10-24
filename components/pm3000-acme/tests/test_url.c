#include "pm3000_acme_url.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_valid(const char *input, const char *host,
                         unsigned int port, const char *path)
{
    struct pm3000_acme_url parsed;
    int result = pm3000_acme_url_parse(input, &parsed);
    if (result != PM3000_ACME_URL_OK || strcmp(parsed.host, host) != 0 ||
        parsed.port != port || strcmp(parsed.path, path) != 0) {
        fprintf(stderr, "expected valid URL: %s\n", input);
        ++failures;
    }
}

static void expect_invalid(const char *input)
{
    struct pm3000_acme_url parsed;
    if (pm3000_acme_url_parse(input, &parsed) == PM3000_ACME_URL_OK) {
        fprintf(stderr, "expected invalid URL: %s\n", input);
        ++failures;
    }
}

static void expect_same_origin(const char *left, const char *right, int expected)
{
    struct pm3000_acme_url left_url;
    struct pm3000_acme_url right_url;
    int actual;

    if (pm3000_acme_url_parse(left, &left_url) != PM3000_ACME_URL_OK ||
        pm3000_acme_url_parse(right, &right_url) != PM3000_ACME_URL_OK) {
        fprintf(stderr, "same-origin fixture invalid\n");
        ++failures;
        return;
    }
    actual = pm3000_acme_url_same_origin(&left_url, &right_url);
    if (actual != expected) {
        fprintf(stderr, "same-origin mismatch: %s / %s\n", left, right);
        ++failures;
    }
}

int main(void)
{
    char long_url[PM3000_ACME_HOST_MAX + 40U];
    size_t index;
    size_t used;

    expect_valid("https://acme.example.test/directory",
                 "acme.example.test", 443U, "/directory");
    expect_valid("https://192.0.2.10:8443/acme/v2",
                 "192.0.2.10", 8443U, "/acme/v2");
    expect_valid("https://ACME.Example.TEST/directory",
                 "acme.example.test", 443U, "/directory");

    expect_invalid("http://acme.example.test/directory");
    expect_invalid("https://user@acme.example.test/directory");
    expect_invalid("https://acme.example.test/directory?tenant=1");
    expect_invalid("https://acme.example.test/directory#fragment");
    expect_invalid("https://acme.example.test");
    expect_invalid("https://acme.example.test:0/directory");
    expect_invalid("https://acme.example.test:65536/directory");
    expect_invalid("https://-acme.example.test/directory");
    expect_invalid("https://acme..example.test/directory");
    expect_invalid("https://acme.example.test/path\\escape");
    expect_invalid("https://acme.example.test/path with-space");
    expect_invalid("");

    expect_same_origin("https://acme.example.test/directory",
                       "https://ACME.EXAMPLE.TEST/new-order", 1);
    expect_same_origin("https://acme.example.test/directory",
                       "https://other.example.test/new-order", 0);
    expect_same_origin("https://acme.example.test/directory",
                       "https://acme.example.test:8443/new-order", 0);

    strcpy(long_url, "https://");
    used = strlen(long_url);
    for (index = 0U; index < PM3000_ACME_HOST_MAX + 2U; ++index) {
        long_url[used++] = (index % 2U) == 0U ? 'a' : '.';
    }
    strcpy(long_url + used, "/directory");
    expect_invalid(long_url);

    if (failures != 0) {
        fprintf(stderr, "url.tests.failed=%d\n", failures);
        return 1;
    }
    puts("url.tests.complete=yes");
    return 0;
}
