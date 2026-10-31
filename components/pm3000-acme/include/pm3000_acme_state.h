#ifndef PM3000_ACME_STATE_H
#define PM3000_ACME_STATE_H

#include "pm3000_acme_client.h"
#include "pm3000_acme_crypto.h"

enum pm3000_acme_state_result {
    PM3000_ACME_STATE_OK = 0,
    PM3000_ACME_STATE_INVALID = -1,
    PM3000_ACME_STATE_IO = -2,
    PM3000_ACME_STATE_UNSAFE = -3,
    PM3000_ACME_STATE_BUSY = -4,
    PM3000_ACME_STATE_NOT_FOUND = -5,
    PM3000_ACME_STATE_COMMITTED_UNCERTAIN = -6
};

struct pm3000_acme_state {
    int root_fd;
    int lock_fd;
    struct pm3000_acme_key account_key;
    struct pm3000_acme_key certificate_key;
};

int pm3000_acme_state_prepare(const char *root,
                              struct pm3000_acme_state *state);
int pm3000_acme_state_open(const char *root,
                           struct pm3000_acme_state *state);
int pm3000_acme_state_open_root(const char *root,
                                struct pm3000_acme_state *state);
int pm3000_acme_state_prepare_locked(struct pm3000_acme_state *state);
void pm3000_acme_state_close(struct pm3000_acme_state *state);
int pm3000_acme_state_store_account_url(
    const struct pm3000_acme_state *state, const char *url);
int pm3000_acme_state_load_account_url(
    const struct pm3000_acme_state *state, char *output,
                                       unsigned int output_capacity);

#endif
