#include "pm3000_acme_protocol.h"

#include <stdio.h>
#include <string.h>

static int failures;

static void expect_order_invalid(const char *json,
                                 const struct pm3000_acme_url *origin,
                                 const char *label)
{
    struct pm3000_acme_order order;
    if (pm3000_acme_order_parse((const unsigned char *)json,
                                (unsigned int)strlen(json), origin,
                                &order) == PM3000_ACME_PROTOCOL_OK) {
        fprintf(stderr, "expected invalid order: %s\n", label);
        ++failures;
    }
}

static void expect_authorization_invalid(const char *json,
                                         const struct pm3000_acme_url *origin,
                                         const char *label)
{
    struct pm3000_acme_authorization authorization;
    if (pm3000_acme_authorization_parse((const unsigned char *)json,
                                        (unsigned int)strlen(json), origin,
                                        &authorization) ==
        PM3000_ACME_PROTOCOL_OK) {
        fprintf(stderr, "expected invalid authorization: %s\n", label);
        ++failures;
    }
}

int main(void)
{
    static const char order_json[] =
        "{\"status\":\"pending\","
        "\"authorizations\":[\"https://acme.example.test/authz/1\","
        "\"https://acme.example.test/authz/2\"],"
        "\"finalize\":\"https://acme.example.test/order/1/finalize\"}";
    static const char authorization_json[] =
        "{\"status\":\"pending\","
        "\"identifier\":{\"type\":\"dns\",\"value\":\"PDU1.TSEI.MDN\"},"
        "\"challenges\":["
        "{\"type\":\"dns-01\",\"url\":\"https://acme.example.test/dns/1\","
        "\"status\":\"pending\",\"token\":\"ignored\"},"
        "{\"type\":\"http-01\",\"url\":\"https://acme.example.test/http/1\","
        "\"status\":\"pending\",\"token\":\"abc_DEF-012\"}]}";
    struct pm3000_acme_url origin;
    struct pm3000_acme_order order;
    struct pm3000_acme_authorization authorization;

    if (pm3000_acme_url_parse("https://acme.example.test/directory", &origin) !=
        PM3000_ACME_URL_OK) return 2;

    if (pm3000_acme_order_parse((const unsigned char *)order_json,
                                sizeof(order_json) - 1U, &origin, &order) !=
            PM3000_ACME_PROTOCOL_OK ||
        order.status != PM3000_ACME_STATUS_PENDING ||
        order.authorization_count != 2U ||
        strcmp(order.authorization_text[1],
               "https://acme.example.test/authz/2") != 0 ||
        strcmp(order.finalize.path, "/order/1/finalize") != 0 ||
        order.have_certificate != 0) {
        fprintf(stderr, "valid order rejected or decoded incorrectly\n");
        ++failures;
    }
    expect_order_invalid(
        "{\"status\":\"pending\",\"authorizations\":[],"
        "\"finalize\":\"https://acme.example.test/f\"}",
        &origin, "empty authorizations");
    expect_order_invalid(
        "{\"status\":\"pending\","
        "\"authorizations\":[\"https://other.example.test/a\"],"
        "\"finalize\":\"https://acme.example.test/f\"}",
        &origin, "cross-origin authorization");
    expect_order_invalid(
        "{\"status\":\"valid\","
        "\"authorizations\":[\"https://acme.example.test/a\"],"
        "\"finalize\":\"https://acme.example.test/f\"}",
        &origin, "valid without certificate");

    if (pm3000_acme_authorization_parse(
            (const unsigned char *)authorization_json,
            sizeof(authorization_json) - 1U, &origin, &authorization) !=
            PM3000_ACME_PROTOCOL_OK ||
        authorization.status != PM3000_ACME_STATUS_PENDING ||
        strcmp(authorization.identifier, "pdu1.tsei.mdn") != 0 ||
        strcmp(authorization.challenge.token, "abc_DEF-012") != 0 ||
        strcmp(authorization.challenge.url.path, "/http/1") != 0) {
        fprintf(stderr, "valid authorization rejected or decoded incorrectly\n");
        ++failures;
    }
    expect_authorization_invalid(
        "{\"status\":\"pending\",\"wildcard\":true,"
        "\"identifier\":{\"type\":\"dns\",\"value\":\"example.test\"},"
        "\"challenges\":[{\"type\":\"http-01\","
        "\"url\":\"https://acme.example.test/c\","
        "\"status\":\"pending\",\"token\":\"abc\"}]}",
        &origin, "wildcard HTTP-01");
    expect_authorization_invalid(
        "{\"status\":\"pending\","
        "\"identifier\":{\"type\":\"dns\",\"value\":\"example.test\"},"
        "\"challenges\":[{\"type\":\"http-01\","
        "\"url\":\"https://acme.example.test/c\","
        "\"status\":\"pending\",\"token\":\"bad/token\"}]}",
        &origin, "invalid token alphabet");
    expect_authorization_invalid(
        "{\"status\":\"pending\","
        "\"identifier\":{\"type\":\"dns\",\"value\":\"example.test\"},"
        "\"challenges\":[]}",
        &origin, "missing HTTP-01 challenge");

    {
        static const char *names[] = {"PDU1.TSEI.MDN", "usv3.tsei.mdn"};
        char payload[1024];
        unsigned int payload_length = 0U;
        if (pm3000_acme_account_parse(
                (const unsigned char *)"{\"status\":\"valid\"}", 18U) !=
                PM3000_ACME_PROTOCOL_OK ||
            pm3000_acme_account_parse(
                (const unsigned char *)"{\"status\":\"deactivated\"}", 24U) ==
                PM3000_ACME_PROTOCOL_OK ||
            !pm3000_acme_error_is_bad_nonce(
                (const unsigned char *)
                    "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}",
                46U) ||
            pm3000_acme_build_order_payload(
                names, 2U, payload, sizeof(payload), &payload_length) !=
                PM3000_ACME_PROTOCOL_OK ||
            strcmp(payload,
                   "{\"identifiers\":[{\"type\":\"dns\",\"value\":"
                   "\"pdu1.tsei.mdn\"},{\"type\":\"dns\",\"value\":"
                   "\"usv3.tsei.mdn\"}]}") != 0 ||
            payload_length != (unsigned int)strlen(payload)) {
            fprintf(stderr, "account/error/order payload contract failed\n");
            ++failures;
        }
        if (pm3000_acme_build_finalize_payload(
                "Y3Ny", payload, sizeof(payload), &payload_length) !=
                PM3000_ACME_PROTOCOL_OK ||
            strcmp(payload, "{\"csr\":\"Y3Ny\"}") != 0) {
            fprintf(stderr, "finalize payload contract failed\n");
            ++failures;
        }
    }

    if (failures != 0) {
        fprintf(stderr, "protocol.tests.failed=%d\n", failures);
        return 1;
    }
    puts("protocol.tests.complete=yes");
    return 0;
}
