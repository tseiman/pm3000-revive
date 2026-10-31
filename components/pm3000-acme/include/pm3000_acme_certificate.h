#ifndef PM3000_ACME_CERTIFICATE_H
#define PM3000_ACME_CERTIFICATE_H

#include "pm3000_acme_crypto.h"

#define PM3000_ACME_CA_BUNDLE_MAX 65536U

enum pm3000_acme_certificate_result {
    PM3000_ACME_CERTIFICATE_OK = 0,
    PM3000_ACME_CERTIFICATE_INVALID = -1,
    PM3000_ACME_CERTIFICATE_IO = -2,
    PM3000_ACME_CERTIFICATE_TRUST = -3,
    PM3000_ACME_CERTIFICATE_KEY = -4,
    PM3000_ACME_CERTIFICATE_NAME = -5
};

int pm3000_acme_certificate_validate(
    const char *certificate_chain_path, const char *ca_file,
    const struct pm3000_acme_key *private_key,
    const char *const *dns_names, unsigned int dns_name_count);
int pm3000_acme_certificate_validate_bytes(
    const unsigned char *certificate_chain, unsigned int certificate_length,
    const char *ca_file, const struct pm3000_acme_key *private_key,
    const char *const *dns_names, unsigned int dns_name_count);
int pm3000_acme_certificate_validate_ca_bundle(
    const unsigned char *bundle, unsigned int bundle_length);

#endif
