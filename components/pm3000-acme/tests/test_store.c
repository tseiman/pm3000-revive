#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_store.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int main(void)
{
    static const unsigned char first[] = "first";
    static const unsigned char second[] = "second-value";
    char root[] = "build/store-root";
    char path[256];
    char outside[] = "build/store-outside";
    unsigned char output[64];
    unsigned int length = 0U;
    struct stat info;
    int fd;
    unlink(outside);
    snprintf(path, sizeof(path), "%s/state", root);
    unlink(path);
    snprintf(path, sizeof(path), "%s/link", root);
    unlink(path);
    rmdir(root);
    if (mkdir(root, 0700) != 0 ||
        pm3000_acme_store_write(root, "state", first,
                                sizeof(first) - 1U, 0600U) !=
            PM3000_ACME_STORE_OK ||
        pm3000_acme_store_read(root, "state", output, sizeof(output),
                               &length, 1) != PM3000_ACME_STORE_OK ||
        length != sizeof(first) - 1U ||
        memcmp(output, first, length) != 0) {
        fprintf(stderr, "store initial write/read failed\n");
        return 1;
    }
    snprintf(path, sizeof(path), "%s/state", root);
    if (stat(path, &info) != 0 || (info.st_mode & 0777U) != 0600U ||
        pm3000_acme_store_write(root, "state", second,
                                sizeof(second) - 1U, 0600U) !=
            PM3000_ACME_STORE_OK ||
        pm3000_acme_store_read(root, "state", output, sizeof(output),
                               &length, 1) != PM3000_ACME_STORE_OK ||
        length != sizeof(second) - 1U ||
        memcmp(output, second, length) != 0) {
        fprintf(stderr, "store atomic replacement failed\n");
        return 1;
    }
    fd = open(outside, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0 || write(fd, "safe", 4U) != 4 || close(fd) != 0) return 2;
    snprintf(path, sizeof(path), "%s/link", root);
    if (symlink("../store-outside", path) != 0 ||
        pm3000_acme_store_read(root, "link", output, sizeof(output),
                               &length, 1) == PM3000_ACME_STORE_OK ||
        pm3000_acme_store_write(root, "../escape", first,
                                sizeof(first) - 1U, 0600U) ==
            PM3000_ACME_STORE_OK) {
        fprintf(stderr, "store traversal/symlink rejection failed\n");
        return 1;
    }
    unlink(path);
    if (link(outside, path) != 0 ||
        pm3000_acme_store_read(root, "link", output, sizeof(output),
                               &length, 1) == PM3000_ACME_STORE_OK) {
        fprintf(stderr, "store hardlink rejection failed\n");
        return 1;
    }
    unlink(path);
    snprintf(path, sizeof(path), "%s/state", root);
    unlink(path);
    unlink(outside);
    rmdir(root);
    puts("store.tests.complete=yes");
    return 0;
}
