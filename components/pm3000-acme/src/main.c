#include "pm3000_acme_app.h"

#define PM3000_ACME_STATE_ROOT "/mnt/hdUser/pm3000-revive/acme"
#define PM3000_ACME_CHALLENGE_ROOT \
    "/mnt/hdUser/pm3000-revive/acme/http-01"

int main(int argc, char **argv)
{
    static const struct pm3000_acme_app_paths paths = {
        PM3000_ACME_STATE_ROOT,
        PM3000_ACME_CHALLENGE_ROOT
    };
    return pm3000_acme_app_run(argc, argv, &paths);
}
