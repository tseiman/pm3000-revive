#ifndef PM3000_ACME_APP_H
#define PM3000_ACME_APP_H

#include "pm3000_acme_client.h"

enum pm3000_acme_app_result {
    PM3000_ACME_APP_OK = 0,
    PM3000_ACME_APP_FAILED = 1,
    PM3000_ACME_APP_USAGE = 2,
    PM3000_ACME_APP_DISABLED = 3,
    PM3000_ACME_APP_BUSY = 4,
    PM3000_ACME_APP_STALE = 5,
    PM3000_ACME_APP_NOT_FOUND = 6
};

struct pm3000_acme_app_paths {
    const char *state_root;
    const char *challenge_webroot;
    const char *managed_ca_file;
};

int pm3000_acme_app_run(int argc, char **argv,
                        const struct pm3000_acme_app_paths *paths);
int pm3000_acme_failure_debug_format(
    const struct pm3000_acme_client_result *failure,
    char *output, unsigned int output_capacity);

#endif
