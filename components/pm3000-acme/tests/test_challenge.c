#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_challenge.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_text(const char *path, const char *text)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    size_t length = strlen(text);
    if (fd < 0 || write(fd, text, length) != (ssize_t)length || close(fd) != 0)
        return 0;
    return 1;
}

int main(void)
{
    char root[] = "build/challenge-root";
    char link_root[] = "build/challenge-link";
    char outside[] = "build/challenge-outside";
    char target[256];
    char content[256];
    struct stat status;
    int fd;
    ssize_t amount;
    int failed = 0;

    unlink(link_root);
    unlink(outside);
    snprintf(target, sizeof(target), "%s/%s", root, "YWJjLTEyMw");
    unlink(target);
    rmdir(root);
    if (mkdir(root, 0755) != 0 || symlink(root, link_root) != 0 ||
        !write_text(outside, "do-not-touch")) return 2;

    if (pm3000_acme_challenge_publish(
            root, "YWJjLTEyMw", "dGh1bWJwcmludA") !=
            PM3000_ACME_CHALLENGE_OK) {
        fprintf(stderr, "challenge publish failed\n");
        failed = 1;
    } else {
        fd = open(target, O_RDONLY);
        amount = fd >= 0 ? read(fd, content, sizeof(content) - 1U) : -1;
        if (fd >= 0) close(fd);
        if (amount < 0) amount = 0;
        content[amount] = '\0';
        if (strcmp(content, "YWJjLTEyMw.dGh1bWJwcmludA") != 0 ||
            stat(target, &status) != 0 || (status.st_mode & 0777) != 0644) {
            fprintf(stderr, "challenge content or mode mismatch\n");
            failed = 1;
        }
    }
    if (pm3000_acme_challenge_publish(
            root, "../escape", "dGh1bWJwcmludA") ==
            PM3000_ACME_CHALLENGE_OK ||
        pm3000_acme_challenge_publish(
            link_root, "YWJjLTEyMw", "dGh1bWJwcmludA") ==
            PM3000_ACME_CHALLENGE_OK) {
        fprintf(stderr, "unsafe token or symlink root accepted\n");
        failed = 1;
    }

    unlink(target);
    if (symlink("../challenge-outside", target) != 0 ||
        pm3000_acme_challenge_publish(
            root, "YWJjLTEyMw", "bmV3") != PM3000_ACME_CHALLENGE_OK) {
        fprintf(stderr, "symlink replacement setup failed\n");
        failed = 1;
    } else {
        fd = open(outside, O_RDONLY);
        amount = read(fd, content, sizeof(content) - 1U);
        close(fd);
        content[amount > 0 ? amount : 0] = '\0';
        if (strcmp(content, "do-not-touch") != 0 || lstat(target, &status) != 0 ||
            S_ISLNK(status.st_mode)) {
            fprintf(stderr, "challenge symlink replacement unsafe\n");
            failed = 1;
        }
    }

    if (pm3000_acme_challenge_remove(root, "YWJjLTEyMw") !=
            PM3000_ACME_CHALLENGE_OK || lstat(target, &status) == 0 ||
        pm3000_acme_challenge_remove(root, "YWJjLTEyMw") !=
            PM3000_ACME_CHALLENGE_OK) {
        fprintf(stderr, "challenge cleanup failed\n");
        failed = 1;
    }
    unlink(link_root);
    unlink(outside);
    rmdir(root);
    if (failed) return 1;
    puts("challenge.tests.complete=yes");
    return 0;
}
