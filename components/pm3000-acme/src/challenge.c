#define _GNU_SOURCE

#include "pm3000_acme_challenge.h"
#include "stat_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define TOKEN_MAX 128U
#define THUMBPRINT_MAX 64U

static int base64url_text(const char *text, unsigned int maximum)
{
    unsigned int index = 0U;
    if (text == (const char *)0) return 0;
    while (text[index] != '\0') {
        char value = text[index];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_'))
            return 0;
        if (++index > maximum) return 0;
    }
    return index != 0U;
}

static int open_webroot(const char *webroot)
{
    int descriptor;
    struct pm3000_acme_stat status;
    if (webroot == (const char *)0 || webroot[0] != '/') {
        /* Relative paths are retained for isolated host tests only. */
        if (webroot == (const char *)0 || webroot[0] == '\0') return -1;
    }
    descriptor = open(webroot, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    if (pm3000_acme_fstat(descriptor, &status) != 0 ||
        !PM3000_ACME_S_ISDIR(status.mode)) {
        close(descriptor);
        return -1;
    }
    return descriptor;
}

static int write_all(int descriptor, const char *first,
                     const char *second, const char *third)
{
    const char *parts[3];
    unsigned int part;
    parts[0] = first;
    parts[1] = second;
    parts[2] = third;
    for (part = 0U; part < 3U; ++part) {
        unsigned int length = 0U;
        unsigned int offset = 0U;
        while (parts[part][length] != '\0') ++length;
        while (offset < length) {
            ssize_t amount = write(descriptor, parts[part] + offset,
                                   length - offset);
            if (amount < 0 && errno == EINTR) continue;
            if (amount <= 0) return 0;
            offset += (unsigned int)amount;
        }
    }
    return 1;
}

int pm3000_acme_challenge_publish(const char *webroot, const char *token,
                                  const char *thumbprint)
{
    int directory;
    int file = -1;
    unsigned int attempt;
    char temporary[96];
    int result = PM3000_ACME_CHALLENGE_IO;
    if (!base64url_text(token, TOKEN_MAX) ||
        !base64url_text(thumbprint, THUMBPRINT_MAX))
        return PM3000_ACME_CHALLENGE_INVALID;
    directory = open_webroot(webroot);
    if (directory < 0) return PM3000_ACME_CHALLENGE_IO;
    for (attempt = 0U; attempt < 16U; ++attempt) {
        int length = snprintf(temporary, sizeof(temporary),
                              ".pm3000-acme-%ld-%u.tmp",
                              (long)getpid(), attempt);
        if (length <= 0 || (unsigned int)length >= sizeof(temporary)) break;
        file = openat(directory, temporary,
                      O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (file >= 0) break;
        if (errno != EEXIST) break;
    }
    if (file < 0) goto cleanup;
    if (!write_all(file, token, ".", thumbprint) || fchmod(file, 0644) != 0 ||
        fsync(file) != 0 || close(file) != 0) {
        if (file >= 0) close(file);
        file = -1;
        unlinkat(directory, temporary, 0);
        goto cleanup;
    }
    file = -1;
    if (renameat(directory, temporary, directory, token) != 0 ||
        fsync(directory) != 0) {
        unlinkat(directory, temporary, 0);
        goto cleanup;
    }
    result = PM3000_ACME_CHALLENGE_OK;
cleanup:
    if (file >= 0) close(file);
    close(directory);
    return result;
}

int pm3000_acme_challenge_remove(const char *webroot, const char *token)
{
    int directory;
    int result;
    if (!base64url_text(token, TOKEN_MAX))
        return PM3000_ACME_CHALLENGE_INVALID;
    directory = open_webroot(webroot);
    if (directory < 0) return PM3000_ACME_CHALLENGE_IO;
    result = unlinkat(directory, token, 0);
    if (result != 0 && errno != ENOENT) {
        close(directory);
        return PM3000_ACME_CHALLENGE_IO;
    }
    if (fsync(directory) != 0) {
        close(directory);
        return PM3000_ACME_CHALLENGE_IO;
    }
    close(directory);
    return PM3000_ACME_CHALLENGE_OK;
}
