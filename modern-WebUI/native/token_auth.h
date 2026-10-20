#ifndef PM3000_TOKEN_AUTH_H
#define PM3000_TOKEN_AUTH_H

#define PM3000_MAX_ALLOWLIST 256U
#define PM3000_OPAQUE_ID_LENGTH 22U

typedef struct {
    int authenticated;
    int authorized;
    int unrestricted;
    unsigned int outlet_count;
    char outlets[PM3000_MAX_ALLOWLIST][PM3000_OPAQUE_ID_LENGTH + 1U];
} pm3000_authorization;

int pm3000_authorize(const char *store_path, const char *plaintext,
                     const char *required_scope, const char *outlet_id,
                     pm3000_authorization *authorization,
                     char *error, unsigned int error_size);

#endif
