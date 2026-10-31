#ifndef PM3000_ACME_ADMIN_CLIENT_H
#define PM3000_ACME_ADMIN_CLIENT_H

#include <stddef.h>

#define PM3000_ACME_ADMIN_CONFIG_SHOW 1U
#define PM3000_ACME_ADMIN_CONFIG_REPLACE 2U
#define PM3000_ACME_ADMIN_CA_INSTALL 3U
#define PM3000_ACME_ADMIN_STATUS 4U
#define PM3000_ACME_ADMIN_CONFIG_REVISION 5U
#define PM3000_ACME_ADMIN_RENEW_ASYNC 6U
#define PM3000_ACME_ADMIN_CONFIG_CREATE 7U
#define PM3000_ACME_ADMIN_CA_CREATE 8U
#define PM3000_ACME_ADMIN_BOOTSTRAP_STATUS 9U

#define PM3000_ACME_ADMIN_ETAG_LENGTH 66U
#define PM3000_ACME_ADMIN_CONFIG_LIMIT 8192U
#define PM3000_ACME_ADMIN_CA_LIMIT 65536U
#define PM3000_ACME_ADMIN_CONFIG_WIRE_LIMIT \
    (PM3000_ACME_ADMIN_ETAG_LENGTH + PM3000_ACME_ADMIN_CONFIG_LIMIT)
#define PM3000_ACME_ADMIN_CA_WIRE_LIMIT \
    (PM3000_ACME_ADMIN_ETAG_LENGTH + PM3000_ACME_ADMIN_CA_LIMIT)
#define PM3000_ACME_ADMIN_OUTPUT_LIMIT 8448U

enum pm3000_acme_admin_result {
    PM3000_ACME_ADMIN_SUCCESS = 0,
    PM3000_ACME_ADMIN_BAD_REQUEST = 1,
    PM3000_ACME_ADMIN_CHILD_FAILED = 2,
    PM3000_ACME_ADMIN_UNAVAILABLE = 3,
    PM3000_ACME_ADMIN_PROTOCOL_ERROR = 4,
    PM3000_ACME_ADMIN_OUTCOME_UNKNOWN = 5,
    PM3000_ACME_ADMIN_BUSY = 6,
    PM3000_ACME_ADMIN_STARTUP_FAILED = 7
};

struct pm3000_acme_admin_response {
    unsigned int child_status;
    size_t output_length;
    unsigned char output[PM3000_ACME_ADMIN_OUTPUT_LIMIT];
};

/* Executes exactly one request through the fixed helper executable at helper_path.
 * helper_path must be absolute. revision must be NULL for reads and exactly one
 * quoted lowercase SHA-256 ETag for mutations. No caller-controlled argv is used.
 */
enum pm3000_acme_admin_result pm3000_acme_admin_call(
    const char *helper_path, unsigned int opcode,
    const char *revision,
    const unsigned char *body, size_t body_length,
    struct pm3000_acme_admin_response *response);

#endif
