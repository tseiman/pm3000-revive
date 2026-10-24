#ifndef PM3000_ACME_HTTP_H
#define PM3000_ACME_HTTP_H

#include "pm3000_acme_url.h"

#define PM3000_ACME_HTTP_HEADER_MAX 16384U
#define PM3000_ACME_HTTP_BODY_MAX 65536U
#define PM3000_ACME_HTTP_NONCE_MAX 256U
#define PM3000_ACME_HTTP_CONTENT_TYPE_MAX 127U
#define PM3000_ACME_HTTP_REQUEST_MAX 18432U

enum pm3000_acme_http_result {
    PM3000_ACME_HTTP_OK = 0,
    PM3000_ACME_HTTP_INVALID = -1,
    PM3000_ACME_HTTP_LIMIT = -2
};

struct pm3000_acme_http_response {
    unsigned int status_code;
    char replay_nonce[PM3000_ACME_HTTP_NONCE_MAX + 1U];
    char location[PM3000_ACME_URL_TEXT_MAX + 1U];
    char content_type[PM3000_ACME_HTTP_CONTENT_TYPE_MAX + 1U];
    unsigned int body_length;
};

int pm3000_acme_http_build_request(
    const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *body,
    unsigned int body_length, char *output, unsigned int output_capacity,
    unsigned int *output_length);
int pm3000_acme_http_parse_response(
    const unsigned char *input, unsigned int input_length,
    const struct pm3000_acme_url *origin,
    struct pm3000_acme_http_response *response,
    unsigned char *body, unsigned int body_capacity);

#endif
