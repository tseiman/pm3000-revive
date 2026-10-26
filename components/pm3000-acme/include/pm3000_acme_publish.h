#ifndef PM3000_ACME_PUBLISH_H
#define PM3000_ACME_PUBLISH_H

#include "pm3000_acme_crypto.h"

enum pm3000_acme_publish_result {
    PM3000_ACME_PUBLISH_OK = 0,
    PM3000_ACME_PUBLISH_INVALID = -1,
    PM3000_ACME_PUBLISH_IO = -2,
    PM3000_ACME_PUBLISH_REJECTED = -3,
    PM3000_ACME_PUBLISH_COMMITTED_UNCERTAIN = -4
};

int pm3000_acme_publish_certificate(
    int state_root_fd, const unsigned char *certificate_pem,
    unsigned int certificate_length, const char *ca_file,
    const struct pm3000_acme_key *certificate_key,
    const char *const *dns_names, unsigned int dns_name_count);

#endif
