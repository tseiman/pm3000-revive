#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_state.h"
#include "pm3000_acme_store.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static int fail_directory_fsync_on;

int __real_fsync(int descriptor);

int __wrap_fsync(int descriptor)
{
    struct stat details;
    if (fail_directory_fsync_on > 0 && fstat(descriptor, &details) == 0 &&
        S_ISDIR(details.st_mode) && --fail_directory_fsync_on == 0) {
        errno = EIO;
        return -1;
    }
    return __real_fsync(descriptor);
}

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
    char account_path[512];
    char certificate_path[512];
    char moved_root[256];
    char moved_account_url[512];
    char replacement_account_url[512];
    unsigned char before[4096U];
    unsigned char after[4096U];
    unsigned int before_length = 0U;
    unsigned int after_length = 0U;
    struct stat details;
    struct pm3000_acme_state first;
    struct pm3000_acme_state second;
    struct pm3000_acme_state reader;
    struct pm3000_acme_state uncertain;
    char uncertain_root[] = "build/state-uncertain-XXXXXX";
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
    if (pm3000_acme_store_write(
            root, "account-url",
            (const unsigned char *)"https://acme.example.test/account/stale",
            (unsigned int)strlen("https://acme.example.test/account/stale"),
            0600) != PM3000_ACME_STORE_OK ||
        pm3000_acme_state_prepare(root, &first) != PM3000_ACME_STATE_OK ||
        pm3000_acme_state_load_account_url(&first, account_url,
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
    if (pm3000_acme_state_open_root(root, &reader) != PM3000_ACME_STATE_OK ||
        reader.root_fd < 0 || reader.lock_fd >= 0) {
        fprintf(stderr, "read-only state root open while locked failed\n");
        return 1;
    }
    pm3000_acme_state_close(&reader);
    pm3000_acme_state_close(&first);
    if (pm3000_acme_state_prepare(root, &second) != PM3000_ACME_STATE_OK ||
        read_key(account_path, after, sizeof(after), &after_length) != 0 ||
        before_length != after_length || memcmp(before, after, before_length) != 0) {
        fprintf(stderr, "state key prepare contract failed\n");
        return 1;
    }
    if (pm3000_acme_state_store_account_url(
            &second, "https://acme.example.test/account/1") != PM3000_ACME_STATE_OK ||
        pm3000_acme_state_load_account_url(&second, account_url,
                                           sizeof(account_url)) !=
            PM3000_ACME_STATE_OK ||
        strcmp(account_url, "https://acme.example.test/account/1") != 0 ||
        pm3000_acme_state_store_account_url(&second, "http://invalid/account") ==
            PM3000_ACME_STATE_OK) {
        fprintf(stderr, "state account URL contract failed\n");
        return 1;
    }
    if (snprintf(moved_root, sizeof(moved_root), "%s-locked", root) < 0 ||
        snprintf(moved_account_url, sizeof(moved_account_url),
                 "%s/account-url", moved_root) < 0 ||
        snprintf(replacement_account_url, sizeof(replacement_account_url),
                 "%s/account-url", root) < 0 ||
        rename(root, moved_root) != 0 || mkdir(root, 0700) != 0 ||
        pm3000_acme_state_store_account_url(
            &second, "https://acme.example.test/account/locked") !=
            PM3000_ACME_STATE_OK ||
        pm3000_acme_state_load_account_url(&second, account_url,
                                           sizeof(account_url)) !=
            PM3000_ACME_STATE_OK ||
        strcmp(account_url, "https://acme.example.test/account/locked") != 0 ||
        stat(moved_account_url, &details) != 0 ||
        lstat(replacement_account_url, &details) == 0) {
        fprintf(stderr, "locked state root substitution contract failed\n");
        return 1;
    }
    pm3000_acme_state_close(&second);
    pm3000_acme_state_close(&first);
    snprintf(account_path, sizeof(account_path), "%s/account-key.pem", moved_root);
    snprintf(certificate_path, sizeof(certificate_path),
             "%s/certificate-key.pem", moved_root);
    unlink(account_path);
    unlink(certificate_path);
    unlink(moved_account_url);
    snprintf(account_path, sizeof(account_path), "%s/renew.lock", moved_root);
    unlink(account_path);
    rmdir(root);
    rmdir(moved_root);
    if (mkdtemp(uncertain_root) == NULL || chmod(uncertain_root, 0700) != 0) {
        fprintf(stderr, "uncertain state setup failed\n");
        return 1;
    }
    fail_directory_fsync_on = 2;
    if (pm3000_acme_state_prepare(uncertain_root, &uncertain) !=
            PM3000_ACME_STATE_COMMITTED_UNCERTAIN ||
        uncertain.account_key.handle == (void *)0 ||
        uncertain.certificate_key.handle == (void *)0) {
        fprintf(stderr, "committed key durability state was lost\n");
        return 1;
    }
    pm3000_acme_state_close(&uncertain);
    snprintf(account_path, sizeof(account_path), "%s/account-key.pem",
             uncertain_root);
    snprintf(certificate_path, sizeof(certificate_path),
             "%s/certificate-key.pem", uncertain_root);
    unlink(account_path);
    unlink(certificate_path);
    snprintf(account_path, sizeof(account_path), "%s/renew.lock",
             uncertain_root);
    unlink(account_path);
    rmdir(uncertain_root);
    puts("state.tests.complete=yes");
    return 0;
}
