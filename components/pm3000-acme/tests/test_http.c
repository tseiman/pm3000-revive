#include "pm3000_acme_http.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_invalid(const char *wire,
                           const struct pm3000_acme_url *origin,
                           const char *message)
{
    struct pm3000_acme_http_response response;
    unsigned char body[PM3000_ACME_HTTP_BODY_MAX + 1U];
    if (pm3000_acme_http_parse_response(
            (const unsigned char *)wire, (unsigned int)strlen(wire), origin,
            &response, body, sizeof(body)) == PM3000_ACME_HTTP_OK) {
        fprintf(stderr, "%s\n", message);
        ++failures;
    }
}

int main(void)
{
    struct pm3000_acme_url origin;
    struct pm3000_acme_http_response response;
    unsigned char body[PM3000_ACME_HTTP_BODY_MAX + 1U];
    char request[2048];
    unsigned int request_length = 0U;
    const char content_response[] =
        "HTTP/1.1 201 Created\r\n"
        "Replay-Nonce: bm9uY2U\r\n"
        "Location: https://acme.example.test/order/1\r\n"
        "Content-Type: application/json\r\n"
        "Content-Length: 11\r\n"
        "Connection: close\r\n\r\n"
        "{\"ok\":true}";
    const char chunked_response[] =
        "HTTP/1.1 200 OK\r\n"
        "Transfer-Encoding: chunked\r\n\r\n"
        "4\r\nWiki\r\n5\r\npedia\r\n0\r\n\r\n";

    if (pm3000_acme_url_parse("https://acme.example.test/directory", &origin) !=
            PM3000_ACME_URL_OK ||
        pm3000_acme_http_parse_response(
            (const unsigned char *)content_response,
            sizeof(content_response) - 1U, &origin, &response, body,
            sizeof(body)) != PM3000_ACME_HTTP_OK ||
        response.status_code != 201U ||
        strcmp(response.replay_nonce, "bm9uY2U") != 0 ||
        strcmp(response.location,
               "https://acme.example.test/order/1") != 0 ||
        response.body_length != 11U ||
        memcmp(body, "{\"ok\":true}", 11U) != 0) {
        fprintf(stderr, "content-length response failed\n");
        ++failures;
    }
    if (pm3000_acme_http_parse_response(
            (const unsigned char *)chunked_response,
            sizeof(chunked_response) - 1U, &origin, &response, body,
            sizeof(body)) != PM3000_ACME_HTTP_OK ||
        response.body_length != 9U || memcmp(body, "Wikipedia", 9U) != 0) {
        fprintf(stderr, "chunked response failed\n");
        ++failures;
    }

    expect_invalid("HTTP/1.1 200 OK\r\nReplay-Nonce: YQ\r\nReplay-Nonce: Yg\r\nContent-Length: 0\r\n\r\n",
                   &origin, "duplicate nonce accepted");
    expect_invalid("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
                   &origin, "content-length plus chunked accepted");
    expect_invalid("HTTP/1.1 200 OK\r\nLocation: https://evil.example/order/1\r\nContent-Length: 0\r\n\r\n",
                   &origin, "cross-origin location accepted");
    expect_invalid("HTTP/1.1 200 OK\r\nX-Test: one\r\n folded\r\nContent-Length: 0\r\n\r\n",
                   &origin, "folded header accepted");
    expect_invalid("HTTP/1.1 200 OK\nContent-Length: 0\n\n",
                   &origin, "bare LF accepted");
    expect_invalid("HTTP/1.1 200 OK\r\nContent-Length: 65537\r\n\r\n",
                   &origin, "oversized body accepted");
    expect_invalid("HTTP/1.1 200 OK\r\nTransfer-Encoding: gzip\r\n\r\n",
                   &origin, "unsupported transfer encoding accepted");

    if (pm3000_acme_http_build_request(
            "POST", &origin, "application/jose+json",
            (const unsigned char *)"{}", 2U, request, sizeof(request),
            &request_length) != PM3000_ACME_HTTP_OK ||
        strcmp(request,
               "POST /directory HTTP/1.1\r\n"
               "Host: acme.example.test\r\n"
               "User-Agent: pm3000-acme/1\r\n"
               "Accept: application/json\r\n"
               "Content-Type: application/jose+json\r\n"
               "Content-Length: 2\r\n"
               "Connection: close\r\n\r\n{}") != 0 ||
        request_length != (unsigned int)strlen(request)) {
        fprintf(stderr, "POST request builder failed\n");
        ++failures;
    }
    if (pm3000_acme_http_build_request(
            "GET", &origin, (const char *)0, (const unsigned char *)0, 0U,
            request, sizeof(request), &request_length) != PM3000_ACME_HTTP_OK ||
        strstr(request, "Content-Length") != NULL ||
        strstr(request, "Content-Type") != NULL) {
        fprintf(stderr, "GET request builder failed\n");
        ++failures;
    }

    if (failures != 0) return 1;
    puts("http.tests.complete=yes");
    return 0;
}
