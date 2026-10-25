#define _GNU_SOURCE

#include "pm3000_acme_state.h"
#include "pm3000_acme_store.h"
#include "pm3000_acme_url.h"
#include "stat_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#define STATE_PATH_MAX 1024U
#define STATE_KEY_PEM_MAX 4096U

static void state_clear(struct pm3000_acme_state *state)
{
    memset(state, 0, sizeof(*state));
    state->root_fd = -1;
    state->lock_fd = -1;
    state->account_key.handle = (void *)0;
    state->certificate_key.handle = (void *)0;
}

static int make_path(const char *root, const char *name, char *output,
                     unsigned int capacity)
{
    int amount;
    if (root == (const char *)0 || name == (const char *)0 ||
        output == (char *)0 || capacity == 0U) return 0;
    amount = snprintf(output, capacity, "%s/%s", root, name);
    return amount > 0 && (unsigned int)amount < capacity;
}

static int lock_state_root(const char *root, int *root_fd_output)
{
    struct pm3000_acme_stat details;
    struct flock lock;
    int root_fd;
    int lock_fd;
    root_fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (root_fd < 0) return -1;
    if (pm3000_acme_fstat(root_fd, &details) != 0 ||
        !PM3000_ACME_S_ISDIR(details.mode) ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0700) {
        close(root_fd);
        return -1;
    }
    lock_fd = openat(root_fd, "renew.lock",
                     O_RDWR | O_CREAT | O_NOFOLLOW | O_NONBLOCK, 0600);
    if (lock_fd < 0) {
        close(root_fd);
        return -1;
    }
    if (pm3000_acme_fstat(lock_fd, &details) != 0 ||
        !PM3000_ACME_S_ISREG(details.mode) || details.nlink != 1 ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0600) {
        close(lock_fd);
        close(root_fd);
        return -1;
    }
    memset(&lock, 0, sizeof(lock));
    lock.l_type = F_WRLCK;
    lock.l_whence = SEEK_SET;
    if (fcntl(lock_fd, F_SETLK, &lock) != 0) {
        int saved = errno;
        close(lock_fd);
        close(root_fd);
        if (saved == EACCES || saved == EAGAIN) return -2;
        return -1;
    }
    *root_fd_output = root_fd;
    return lock_fd;
}

static int load_or_create_key(const char *root, int root_fd,
                              const char *name, const char *invalidate_name,
                              struct pm3000_acme_key *key, int *created)
{
    unsigned char existing[STATE_KEY_PEM_MAX];
    unsigned char generated[STATE_KEY_PEM_MAX];
    unsigned int length = 0U;
    char path[STATE_PATH_MAX + 1U];
    int read_result;
    *created = 0;
    if (!make_path(root, name, path, sizeof(path)))
        return PM3000_ACME_STATE_INVALID;
    read_result = pm3000_acme_store_read(root, name, existing,
                                         sizeof(existing), &length, 1);
    if (read_result == PM3000_ACME_STORE_OK) {
        if (length == 0U || length >= sizeof(existing))
            return PM3000_ACME_STATE_UNSAFE;
        existing[length] = '\0';
        return pm3000_acme_crypto_key_load_pem(existing, length, key) ==
                       PM3000_ACME_CRYPTO_OK
                   ? PM3000_ACME_STATE_OK : PM3000_ACME_STATE_UNSAFE;
    }
    {
        struct pm3000_acme_stat unexpected;
        if (pm3000_acme_lstat(path, &unexpected) == 0 || errno != ENOENT)
            return PM3000_ACME_STATE_UNSAFE;
    }
    if (invalidate_name != (const char *)0) {
        if (unlinkat(root_fd, invalidate_name, 0) != 0 && errno != ENOENT)
            return PM3000_ACME_STATE_IO;
        if (fsync(root_fd) != 0) return PM3000_ACME_STATE_IO;
    }
    if (pm3000_acme_crypto_key_generate_rsa2048(key) !=
            PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_pem(key, generated, sizeof(generated),
                                   &length) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_store_write(root, name, generated, length, 0600) !=
            PM3000_ACME_STORE_OK) {
        pm3000_acme_crypto_key_free(key);
        return PM3000_ACME_STATE_IO;
    }
    memset(generated, 0, sizeof(generated));
    *created = 1;
    return PM3000_ACME_STATE_OK;
}

int pm3000_acme_state_prepare(const char *root,
                              struct pm3000_acme_state *state)
{
    int result;
    int account_created = 0;
    int certificate_created = 0;
    if (root == (const char *)0 || state == (struct pm3000_acme_state *)0)
        return PM3000_ACME_STATE_INVALID;
    state_clear(state);
    state->lock_fd = lock_state_root(root, &state->root_fd);
    if (state->lock_fd == -2) {
        state->lock_fd = -1;
        return PM3000_ACME_STATE_BUSY;
    }
    if (state->lock_fd < 0) return PM3000_ACME_STATE_UNSAFE;
    result = load_or_create_key(root, state->root_fd, "account-key.pem",
                                "account-url", &state->account_key,
                                &account_created);
    if (result == PM3000_ACME_STATE_OK)
        result = load_or_create_key(root, state->root_fd,
                                    "certificate-key.pem", (const char *)0,
                                    &state->certificate_key,
                                    &certificate_created);
    if (result != PM3000_ACME_STATE_OK) pm3000_acme_state_close(state);
    return result;
}

void pm3000_acme_state_close(struct pm3000_acme_state *state)
{
    if (state == (struct pm3000_acme_state *)0) return;
    pm3000_acme_crypto_key_free(&state->certificate_key);
    pm3000_acme_crypto_key_free(&state->account_key);
    if (state->lock_fd >= 0) close(state->lock_fd);
    if (state->root_fd >= 0) close(state->root_fd);
    state_clear(state);
}

int pm3000_acme_state_store_account_url(const char *root, const char *url)
{
    struct pm3000_acme_url parsed;
    unsigned int length;
    if (url == (const char *)0 ||
        pm3000_acme_url_parse(url, &parsed) != PM3000_ACME_URL_OK)
        return PM3000_ACME_STATE_INVALID;
    length = (unsigned int)strlen(url);
    if (length == 0U || length > PM3000_ACME_KID_MAX)
        return PM3000_ACME_STATE_INVALID;
    {
        int store_result = pm3000_acme_store_write(
            root, "account-url", (const unsigned char *)url, length, 0600);
        if (store_result == PM3000_ACME_STORE_OK)
            return PM3000_ACME_STATE_OK;
        if (store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
            return PM3000_ACME_STATE_COMMITTED_UNCERTAIN;
        return PM3000_ACME_STATE_IO;
    }
}

int pm3000_acme_state_load_account_url(const char *root, char *output,
                                       unsigned int output_capacity)
{
    struct pm3000_acme_url parsed;
    struct pm3000_acme_stat details;
    char path[STATE_PATH_MAX + 1U];
    unsigned int length = 0U;
    if (output == (char *)0 || output_capacity < 2U ||
        !make_path(root, "account-url", path, sizeof(path)))
        return PM3000_ACME_STATE_INVALID;
    output[0] = '\0';
    if (pm3000_acme_lstat(path, &details) != 0) {
        if (errno == ENOENT) return PM3000_ACME_STATE_NOT_FOUND;
        return PM3000_ACME_STATE_IO;
    }
    if (pm3000_acme_store_read(root, "account-url",
                               (unsigned char *)output,
                               output_capacity - 1U, &length, 1) !=
            PM3000_ACME_STORE_OK || length == 0U ||
        length >= output_capacity) return PM3000_ACME_STATE_IO;
    output[length] = '\0';
    if (pm3000_acme_url_parse(output, &parsed) != PM3000_ACME_URL_OK) {
        output[0] = '\0';
        return PM3000_ACME_STATE_UNSAFE;
    }
    return PM3000_ACME_STATE_OK;
}
