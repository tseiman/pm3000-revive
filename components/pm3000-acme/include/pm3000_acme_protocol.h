#ifndef PM3000_ACME_PROTOCOL_H
#define PM3000_ACME_PROTOCOL_H

#include "pm3000_acme_url.h"

enum pm3000_acme_protocol_result {
    PM3000_ACME_PROTOCOL_OK = 0,
    PM3000_ACME_PROTOCOL_INVALID = -1,
    PM3000_ACME_PROTOCOL_LIMIT = -2
};

#define PM3000_ACME_MAX_IDENTIFIERS 16U
#define PM3000_ACME_TOKEN_MAX 128U

enum pm3000_acme_status {
    PM3000_ACME_STATUS_NONE = 0,
    PM3000_ACME_STATUS_PENDING,
    PM3000_ACME_STATUS_READY,
    PM3000_ACME_STATUS_PROCESSING,
    PM3000_ACME_STATUS_VALID,
    PM3000_ACME_STATUS_INVALID,
    PM3000_ACME_STATUS_DEACTIVATED,
    PM3000_ACME_STATUS_EXPIRED,
    PM3000_ACME_STATUS_REVOKED
};

struct pm3000_acme_directory {
    char new_nonce_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    char new_account_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    char new_order_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    struct pm3000_acme_url new_nonce;
    struct pm3000_acme_url new_account;
    struct pm3000_acme_url new_order;
};

struct pm3000_acme_order {
    enum pm3000_acme_status status;
    unsigned int authorization_count;
    char authorization_text[PM3000_ACME_MAX_IDENTIFIERS]
                           [PM3000_ACME_URL_TEXT_MAX + 1U];
    char finalize_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    struct pm3000_acme_url finalize;
    int have_certificate;
    char certificate_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    struct pm3000_acme_url certificate;
};

struct pm3000_acme_challenge {
    enum pm3000_acme_status status;
    char token[PM3000_ACME_TOKEN_MAX + 1U];
    char url_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    struct pm3000_acme_url url;
};

struct pm3000_acme_authorization {
    enum pm3000_acme_status status;
    char identifier[PM3000_ACME_HOST_MAX + 1U];
    struct pm3000_acme_challenge challenge;
};

int pm3000_acme_directory_parse(const unsigned char *json,
                                unsigned int json_length,
                                const struct pm3000_acme_url *origin,
                                struct pm3000_acme_directory *directory);
int pm3000_acme_order_parse(const unsigned char *json,
                            unsigned int json_length,
                            const struct pm3000_acme_url *origin,
                            struct pm3000_acme_order *order);
int pm3000_acme_authorization_parse(
    const unsigned char *json, unsigned int json_length,
    const struct pm3000_acme_url *origin,
    struct pm3000_acme_authorization *authorization);
int pm3000_acme_account_parse(const unsigned char *json,
                              unsigned int json_length);
int pm3000_acme_error_is_bad_nonce(const unsigned char *json,
                                   unsigned int json_length);
int pm3000_acme_build_order_payload(
    const char *const *dns_names, unsigned int dns_name_count,
    char *output, unsigned int output_capacity,
    unsigned int *output_length);
int pm3000_acme_build_finalize_payload(
    const char *csr_base64url, char *output, unsigned int output_capacity,
    unsigned int *output_length);

#endif
