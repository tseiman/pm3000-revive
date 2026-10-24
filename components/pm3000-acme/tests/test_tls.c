#include "pm3000_acme_tls.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char **argv)
{
    struct pm3000_acme_url url;
    struct pm3000_acme_tls_connection connection;
    char url_text[128];
    static const unsigned char request[] =
        "GET / HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    unsigned char response[4096];
    unsigned int amount = 0U;
    int failed = 0;

    {
        int exact = pm3000_acme_tls_certificate_file_matches(
            "tests/fixtures/tls/server.pem", "ACME.EXAMPLE.TEST");
        int wildcard = pm3000_acme_tls_certificate_file_matches(
            "tests/fixtures/tls/server.pem", "node.wild.example.test");
        int deep = pm3000_acme_tls_certificate_file_matches(
            "tests/fixtures/tls/server.pem", "deep.node.wild.example.test");
        int other = pm3000_acme_tls_certificate_file_matches(
            "tests/fixtures/tls/server.pem", "other.example.test");
        if (exact != PM3000_ACME_TLS_OK || wildcard != PM3000_ACME_TLS_OK ||
            deep == PM3000_ACME_TLS_OK || other == PM3000_ACME_TLS_OK) {
            fprintf(stderr,
                    "certificate hostname contract failed exact=%d wildcard=%d deep=%d other=%d\n",
                    exact, wildcard, deep, other);
            failed = 1;
        }
    }
    if (argc != 2) {
        fprintf(stderr, "usage: test_tls PORT\n");
        return 2;
    }
    {
        int formatted = snprintf(url_text, sizeof(url_text),
                                 "https://localhost:%s/", argv[1]);
        int parsed = formatted > 0 ? pm3000_acme_url_parse(url_text, &url) :
                                     PM3000_ACME_URL_INVALID;
        int connected = parsed == PM3000_ACME_URL_OK
                            ? pm3000_acme_tls_connect(
                                  &url, "tests/fixtures/tls/ca.pem", 5U,
                                  &connection)
                            : PM3000_ACME_TLS_INVALID;
        int written = connected == PM3000_ACME_TLS_OK
                          ? pm3000_acme_tls_write_all(
                                &connection, request, sizeof(request) - 1U)
                          : PM3000_ACME_TLS_INVALID;
        int read_result = written == PM3000_ACME_TLS_OK
                              ? pm3000_acme_tls_read(
                                    &connection, response,
                                    sizeof(response) - 1U, &amount)
                              : PM3000_ACME_TLS_INVALID;
        if (formatted <= 0 || parsed != PM3000_ACME_URL_OK ||
            connected != PM3000_ACME_TLS_OK ||
            written != PM3000_ACME_TLS_OK ||
            read_result != PM3000_ACME_TLS_OK) {
            fprintf(stderr,
                    "trusted TLS loopback failed parsed=%d connected=%d written=%d read=%d\n",
                    parsed, connected, written, read_result);
            if (connected == PM3000_ACME_TLS_OK)
                pm3000_acme_tls_close(&connection);
            failed = 1;
        } else {
            response[amount] = '\0';
            if (strstr((const char *)response, "HTTP/1.0 200") == NULL &&
                strstr((const char *)response, "HTTP/1.1 200") == NULL) {
                fprintf(stderr, "unexpected TLS HTTP response\n");
                failed = 1;
            }
            pm3000_acme_tls_close(&connection);
        }
    }

    if (pm3000_acme_tls_connect(&url, "tests/fixtures/account-test-key.pem",
                                5U, &connection) == PM3000_ACME_TLS_OK) {
        fprintf(stderr, "invalid CA file accepted\n");
        pm3000_acme_tls_close(&connection);
        failed = 1;
    }

    if (failed) return 1;
    puts("tls.tests.complete=yes");
    return 0;
}
