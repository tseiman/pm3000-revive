#include "pm3000_acme_transport.h"
#include "pm3000_acme_tls.h"

int pm3000_acme_transport_exchange(
    void *context, const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *request_body,
    unsigned int request_body_length,
    struct pm3000_acme_http_response *response,
    unsigned char *response_body, unsigned int response_body_capacity)
{
    struct pm3000_acme_transport *transport =
        (struct pm3000_acme_transport *)context;
    struct pm3000_acme_tls_connection connection;
    unsigned int request_length;
    unsigned int wire_length = 0U;
    unsigned int amount;
    int tls_result;
    int result = PM3000_ACME_EXCHANGE_TLS;
    if (transport == (struct pm3000_acme_transport *)0 ||
        transport->ca_file == (const char *)0 ||
        transport->timeout_seconds == 0U ||
        transport->workspace ==
            (struct pm3000_acme_transport_workspace *)0 ||
        response == (struct pm3000_acme_http_response *)0 ||
        response_body == (unsigned char *)0 || response_body_capacity == 0U)
        return PM3000_ACME_EXCHANGE_HTTP;
    if (pm3000_acme_http_build_request(
            method, url, content_type, request_body, request_body_length,
            transport->workspace->request,
            sizeof(transport->workspace->request), &request_length) !=
        PM3000_ACME_HTTP_OK) return PM3000_ACME_EXCHANGE_HTTP;
    if (pm3000_acme_tls_connect(url, transport->ca_file,
                                transport->timeout_seconds,
                                &connection) != PM3000_ACME_TLS_OK)
        return PM3000_ACME_EXCHANGE_TLS;
    if (pm3000_acme_tls_write_all(
            &connection,
            (const unsigned char *)transport->workspace->request,
            request_length) != PM3000_ACME_TLS_OK)
        goto done;
    for (;;) {
        if (wire_length == sizeof(transport->workspace->wire)) goto done;
        tls_result = pm3000_acme_tls_read(
            &connection, transport->workspace->wire + wire_length,
            sizeof(transport->workspace->wire) - wire_length, &amount);
        if (tls_result == PM3000_ACME_TLS_EOF) break;
        if (tls_result != PM3000_ACME_TLS_OK || amount == 0U) goto done;
        wire_length += amount;
    }
    if (pm3000_acme_http_parse_response(
            method, transport->workspace->wire, wire_length, url, response,
            response_body, response_body_capacity) != PM3000_ACME_HTTP_OK)
        result = PM3000_ACME_EXCHANGE_HTTP;
    else
        result = PM3000_ACME_EXCHANGE_OK;
done:
    pm3000_acme_tls_close(&connection);
    return result;
}
