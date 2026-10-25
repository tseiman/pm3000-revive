#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_app.h"
#include "pm3000_acme_store.h"

#include <stdio.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char root[] = "build/app-test-XXXXXX";
    char challenge[] = "build/app-challenge-XXXXXX";
    char key_path[256];
    struct pm3000_acme_app_paths paths;
    char *renew[] = { (char *)"pm3000-acme", (char *)"renew",
                      (char *)"--foreground", (char *)"--debug" };
    char *bad[] = { (char *)"pm3000-acme", (char *)"shell" };
    static const unsigned char disabled[] =
        "{\"enabled\":false,\"directory_url\":\"https://acme.example.test/d\","
        "\"ca_file\":\"/etc/CA/root.pem\",\"dns_names\":[\"pdu1.tsei.mdn\"]}";
    if (mkdtemp(root) == NULL || mkdtemp(challenge) == NULL ||
        chmod(root, 0700) != 0 || chmod(challenge, 0700) != 0 ||
        pm3000_acme_store_write(root, "config.json", disabled,
                                sizeof(disabled) - 1U, 0600) !=
            PM3000_ACME_STORE_OK) return 2;
    paths.state_root = root;
    paths.challenge_webroot = challenge;
    if (pm3000_acme_app_run(2, bad, &paths) != PM3000_ACME_APP_USAGE ||
        pm3000_acme_app_run(4, renew, &paths) != PM3000_ACME_APP_DISABLED ||
        snprintf(key_path, sizeof(key_path), "%s/account-key.pem", root) < 0 ||
        access(key_path, F_OK) == 0) {
        fprintf(stderr, "app argument/disabled contract failed\n");
        return 1;
    }
    puts("app.tests.complete=yes");
    return 0;
}
