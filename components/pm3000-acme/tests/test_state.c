#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_state.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int read_key(const char *path, unsigned char *data,
                    unsigned int capacity, unsigned int *length)
{
    FILE *file = fopen(path, "rb");
    size_t amount;
    if (file == NULL) return -1;
    amount = fread(data, 1U, capacity, file);
    if (ferror(file) || !feof(file) || fclose(file) != 0) return -1;
    *length = (unsigned int)amount;
    return 0;
}

int main(void)
{
    char root[] = "build/state-test-XXXXXX";
    char account_path[256];
    char certificate_path[256];
    unsigned char before[4096U];
    unsigned char after[4096U];
    unsigned int before_length = 0U;
    unsigned int after_length = 0U;
    struct stat details;
    struct pm3000_acme_state first;
    struct pm3000_acme_state second;
    char account_url[PM3000_ACME_KID_MAX + 1U];
    pid_t child;
    int child_status;

    if (mkdtemp(root) == NULL || chmod(root, 0700) != 0 ||
        snprintf(account_path, sizeof(account_path), "%s/account-key.pem", root) < 0 ||
        snprintf(certificate_path, sizeof(certificate_path), "%s/certificate-key.pem", root) < 0) {
        fprintf(stderr, "state test setup failed\n");
        return 1;
    }
    if (symlink("missing-target", account_path) != 0 ||
        pm3000_acme_state_prepare(root, &first) != PM3000_ACME_STATE_UNSAFE ||
        unlink(account_path) != 0) {
        fprintf(stderr, "state symlink rejection failed\n");
        return 1;
    }
    if (pm3000_acme_state_store_account_url(
            root, "https://acme.example.test/account/stale") !=
            PM3000_ACME_STATE_OK ||
        pm3000_acme_state_prepare(root, &first) != PM3000_ACME_STATE_OK ||
        pm3000_acme_state_load_account_url(root, account_url,
                                           sizeof(account_url)) !=
            PM3000_ACME_STATE_NOT_FOUND ||
        stat(account_path, &details) != 0 || (details.st_mode & 0777) != 0600 ||
        stat(certificate_path, &details) != 0 || (details.st_mode & 0777) != 0600 ||
        read_key(account_path, before, sizeof(before), &before_length) != 0) {
        fprintf(stderr, "state key prepare contract failed\n");
        return 1;
    }
    child = fork();
    if (child == 0) {
        struct pm3000_acme_state competing;
        _exit(pm3000_acme_state_prepare(root, &competing) ==
                      PM3000_ACME_STATE_BUSY ? 0 : 1);
    }
    if (child < 0 || waitpid(child, &child_status, 0) != child ||
        !WIFEXITED(child_status) || WEXITSTATUS(child_status) != 0) {
        fprintf(stderr, "state lock contract failed\n");
        return 1;
    }
    pm3000_acme_state_close(&first);
    if (pm3000_acme_state_prepare(root, &second) != PM3000_ACME_STATE_OK ||
        read_key(account_path, after, sizeof(after), &after_length) != 0 ||
        before_length != after_length || memcmp(before, after, before_length) != 0) {
        fprintf(stderr, "state key prepare contract failed\n");
        return 1;
    }
    if (pm3000_acme_state_store_account_url(
            root, "https://acme.example.test/account/1") != PM3000_ACME_STATE_OK ||
        pm3000_acme_state_load_account_url(root, account_url,
                                           sizeof(account_url)) !=
            PM3000_ACME_STATE_OK ||
        strcmp(account_url, "https://acme.example.test/account/1") != 0 ||
        pm3000_acme_state_store_account_url(root, "http://invalid/account") ==
            PM3000_ACME_STATE_OK) {
        fprintf(stderr, "state account URL contract failed\n");
        return 1;
    }
    pm3000_acme_state_close(&second);
    pm3000_acme_state_close(&first);
    unlink(account_path);
    unlink(certificate_path);
    snprintf(account_path, sizeof(account_path), "%s/account-url", root);
    unlink(account_path);
    rmdir(root);
    puts("state.tests.complete=yes");
    return 0;
}
