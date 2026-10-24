#ifndef PM3000_ACME_CHALLENGE_H
#define PM3000_ACME_CHALLENGE_H

enum pm3000_acme_challenge_result {
    PM3000_ACME_CHALLENGE_OK = 0,
    PM3000_ACME_CHALLENGE_INVALID = -1,
    PM3000_ACME_CHALLENGE_IO = -2
};

int pm3000_acme_challenge_publish(const char *webroot, const char *token,
                                  const char *thumbprint);
int pm3000_acme_challenge_remove(const char *webroot, const char *token);

#endif
