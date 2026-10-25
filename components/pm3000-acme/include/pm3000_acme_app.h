#ifndef PM3000_ACME_APP_H
#define PM3000_ACME_APP_H

enum pm3000_acme_app_result {
    PM3000_ACME_APP_OK = 0,
    PM3000_ACME_APP_FAILED = 1,
    PM3000_ACME_APP_USAGE = 2,
    PM3000_ACME_APP_DISABLED = 3,
    PM3000_ACME_APP_BUSY = 4
};

struct pm3000_acme_app_paths {
    const char *state_root;
    const char *challenge_webroot;
};

int pm3000_acme_app_run(int argc, char **argv,
                        const struct pm3000_acme_app_paths *paths);

#endif
