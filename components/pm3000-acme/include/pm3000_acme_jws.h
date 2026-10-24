#ifndef PM3000_ACME_JWS_H
#define PM3000_ACME_JWS_H

#include "pm3000_acme_crypto.h"

#define PM3000_ACME_JWS_PAYLOAD_MAX 8192U
#define PM3000_ACME_JWS_PROTECTED_MAX 2600U
#define PM3000_ACME_JWS_PAYLOAD_B64_MAX 11000U
#define PM3000_ACME_JWS_MAX 16384U
#define PM3000_ACME_NONCE_MAX 256U

enum pm3000_acme_jws_result {
    PM3000_ACME_JWS_OK = 0,
    PM3000_ACME_JWS_INVALID = -1,
    PM3000_ACME_JWS_LIMIT = -2,
    PM3000_ACME_JWS_CRYPTO = -3
};

int pm3000_acme_jws_create(const struct pm3000_acme_key *key,
                           const char *nonce, const char *url,
                           const char *account_kid,
                           const unsigned char *payload,
                           unsigned int payload_length,
                           char *output, unsigned int output_capacity);

#endif
