#ifndef PM3000_ACME_CLIENT_H
#define PM3000_ACME_CLIENT_H

#include "pm3000_acme_crypto.h"
#include "pm3000_acme_http.h"
#include "pm3000_acme_jws.h"

#define PM3000_ACME_KID_MAX PM3000_ACME_URL_TEXT_MAX
#define PM3000_ACME_CERTIFICATE_MAX PM3000_ACME_HTTP_BODY_MAX
#define PM3000_ACME_POLL_ATTEMPTS_MAX 20U

enum pm3000_acme_failure_phase {
    PM3000_ACME_PHASE_NONE = 0,
    PM3000_ACME_PHASE_DIRECTORY,
    PM3000_ACME_PHASE_NONCE,
    PM3000_ACME_PHASE_ACCOUNT,
    PM3000_ACME_PHASE_ORDER,
    PM3000_ACME_PHASE_AUTHORIZATION,
    PM3000_ACME_PHASE_CHALLENGE_PUBLICATION,
    PM3000_ACME_PHASE_CHALLENGE_ACCEPTANCE,
    PM3000_ACME_PHASE_CHALLENGE_POLL,
    PM3000_ACME_PHASE_FINALIZE,
    PM3000_ACME_PHASE_CERTIFICATE_DOWNLOAD,
    PM3000_ACME_PHASE_CERTIFICATE_VALIDATION,
    PM3000_ACME_PHASE_CERTIFICATE_PUBLICATION
};

enum pm3000_acme_failure_reason {
    PM3000_ACME_REASON_NONE = 0,
    PM3000_ACME_REASON_TLS,
    PM3000_ACME_REASON_HTTP,
    PM3000_ACME_REASON_PARSE,
    PM3000_ACME_REASON_IO,
    PM3000_ACME_REASON_REJECTED,
    PM3000_ACME_REASON_TIMEOUT,
    PM3000_ACME_REASON_VALIDATION,
    PM3000_ACME_REASON_PUBLICATION
};

enum pm3000_acme_problem {
    PM3000_ACME_PROBLEM_NONE = 0,
    PM3000_ACME_PROBLEM_UNAUTHORIZED,
    PM3000_ACME_PROBLEM_CONNECTION,
    PM3000_ACME_PROBLEM_DNS,
    PM3000_ACME_PROBLEM_MALFORMED,
    PM3000_ACME_PROBLEM_REJECTED_IDENTIFIER,
    PM3000_ACME_PROBLEM_RATE_LIMITED,
    PM3000_ACME_PROBLEM_SERVER_INTERNAL,
    PM3000_ACME_PROBLEM_TLS,
    PM3000_ACME_PROBLEM_INCORRECT_RESPONSE,
    PM3000_ACME_PROBLEM_ORDER_NOT_READY,
    PM3000_ACME_PROBLEM_UNKNOWN
};

enum pm3000_acme_exchange_result {
    PM3000_ACME_EXCHANGE_OK = 0,
    PM3000_ACME_EXCHANGE_TLS = -1,
    PM3000_ACME_EXCHANGE_HTTP = -2
};

struct pm3000_acme_client_config {
    const char *directory_url;
    const char *existing_account_url;
    const char *challenge_webroot;
    const char *const *dns_names;
    unsigned int dns_name_count;
    unsigned int poll_attempts;
    struct pm3000_acme_key *account_key;
    struct pm3000_acme_key *certificate_key;
};

struct pm3000_acme_client_result {
    char account_url[PM3000_ACME_KID_MAX + 1U];
    unsigned char certificate_pem[PM3000_ACME_CERTIFICATE_MAX + 1U];
    unsigned int certificate_length;
    enum pm3000_acme_failure_phase failure_phase;
    enum pm3000_acme_failure_reason failure_reason;
    unsigned int http_status_code;
    enum pm3000_acme_problem problem;
};

struct pm3000_acme_client_workspace {
    char payload[PM3000_ACME_JWS_PAYLOAD_MAX + 1U];
    char jws[PM3000_ACME_JWS_MAX + 1U];
    unsigned char response_body[PM3000_ACME_HTTP_BODY_MAX + 1U];
    unsigned char csr_der[PM3000_ACME_CSR_DER_MAX];
    char csr_base64url[6001U];
};

typedef int (*pm3000_acme_exchange_fn)(
    void *context, const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *request_body,
    unsigned int request_body_length,
    struct pm3000_acme_http_response *response,
    unsigned char *response_body, unsigned int response_body_capacity);

typedef int (*pm3000_acme_sleep_fn)(void *context, unsigned int seconds);

struct pm3000_acme_client_io {
    pm3000_acme_exchange_fn exchange;
    pm3000_acme_sleep_fn sleep;
    void *context;
};

enum pm3000_acme_client_status {
    PM3000_ACME_CLIENT_OK = 0,
    PM3000_ACME_CLIENT_INVALID = -1,
    PM3000_ACME_CLIENT_IO = -2,
    PM3000_ACME_CLIENT_PROTOCOL = -3,
    PM3000_ACME_CLIENT_REJECTED = -4,
    PM3000_ACME_CLIENT_TIMEOUT = -5
};

int pm3000_acme_client_issue(
    const struct pm3000_acme_client_config *config,
    const struct pm3000_acme_client_io *io,
    struct pm3000_acme_client_workspace *workspace,
    struct pm3000_acme_client_result *result);
const char *pm3000_acme_failure_phase_name(enum pm3000_acme_failure_phase phase);
const char *pm3000_acme_failure_reason_name(enum pm3000_acme_failure_reason reason);
const char *pm3000_acme_problem_name(enum pm3000_acme_problem problem);

#endif
