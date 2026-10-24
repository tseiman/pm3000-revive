#ifndef PM3000_ACME_TRANSPORT_H
#define PM3000_ACME_TRANSPORT_H

#include "pm3000_acme_client.h"

#define PM3000_ACME_HTTP_WIRE_MAX \
    (PM3000_ACME_HTTP_HEADER_MAX + PM3000_ACME_HTTP_BODY_MAX + 1024U)

struct pm3000_acme_transport_workspace {
    char request[PM3000_ACME_HTTP_REQUEST_MAX];
    unsigned char wire[PM3000_ACME_HTTP_WIRE_MAX];
};

struct pm3000_acme_transport {
    const char *ca_file;
    unsigned int timeout_seconds;
    struct pm3000_acme_transport_workspace *workspace;
};

int pm3000_acme_transport_exchange(
    void *context, const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *request_body,
    unsigned int request_body_length,
    struct pm3000_acme_http_response *response,
    unsigned char *response_body, unsigned int response_body_capacity);

#endif
