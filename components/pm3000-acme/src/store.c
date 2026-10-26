#define _GNU_SOURCE

#include "pm3000_acme_store.h"
#include "stat_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define STORE_FILE_MAX 65536U

static int safe_name(const char *name)
{
    unsigned int index = 0U;
    if (name == (const char *)0 || name[0] == '\0' || name[0] == '.') return 0;
    while (name[index] != '\0') {
        char value = name[index];
        if (!((value >= 'a' && value <= 'z') ||
              (value >= 'A' && value <= 'Z') ||
              (value >= '0' && value <= '9') || value == '-' ||
              value == '_' || value == '.')) return 0;
        if (++index > 128U) return 0;
    }
    return 1;
}

static int valid_root_fd(int root_fd)
{
    struct pm3000_acme_stat info;
    return root_fd >= 0 && pm3000_acme_fstat(root_fd, &info) == 0 &&
           PM3000_ACME_S_ISDIR(info.mode) && (info.mode & 077U) == 0U &&
           info.uid == (unsigned long)geteuid();
}

static int open_root(const char *root)
{
    int fd;
    if (root == (const char *)0 || root[0] == '\0') return -1;
    fd = open(root, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (fd < 0) return -1;
    if (!valid_root_fd(fd)) {
        close(fd);
        return -1;
    }
    return fd;
}

static int write_all(int fd, const unsigned char *data, unsigned int length)
{
    unsigned int offset = 0U;
    while (offset < length) {
        ssize_t amount = write(fd, data + offset, length - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return 0;
        offset += (unsigned int)amount;
    }
    return 1;
}

int pm3000_acme_store_write_at(int root_fd, const char *name,
                               const unsigned char *data,
                               unsigned int data_length,
                               unsigned int mode)
{
    int file_fd = -1;
    int result = PM3000_ACME_STORE_IO;
    char temporary[96];
    unsigned int attempt;
    if (!safe_name(name) || (data == (const unsigned char *)0 &&
                             data_length != 0U) ||
        data_length > STORE_FILE_MAX || (mode != 0600U && mode != 0644U))
        return PM3000_ACME_STORE_INVALID;
    if (!valid_root_fd(root_fd)) return PM3000_ACME_STORE_UNSAFE;
    temporary[0] = '\0';
    for (attempt = 0U; attempt < 16U; ++attempt) {
        int count = snprintf(temporary, sizeof(temporary),
                             ".pm3000-acme-%ld-%u.tmp",
                             (long)getpid(), attempt);
        if (count <= 0 || (unsigned int)count >= sizeof(temporary)) goto done;
        file_fd = openat(root_fd, temporary,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600);
        if (file_fd >= 0) break;
        if (errno != EEXIST) goto done;
    }
    if (file_fd < 0 || fchmod(file_fd, mode) != 0 ||
        !write_all(file_fd, data, data_length) || fsync(file_fd) != 0)
        goto done;
    if (close(file_fd) != 0) {
        file_fd = -1;
        goto done;
    }
    file_fd = -1;
    if (renameat(root_fd, temporary, root_fd, name) != 0) goto done;
    temporary[0] = '\0';
    result = fsync(root_fd) == 0 ? PM3000_ACME_STORE_OK :
             PM3000_ACME_STORE_COMMITTED_UNCERTAIN;
done:
    if (file_fd >= 0) close(file_fd);
    if (temporary[0] != '\0') unlinkat(root_fd, temporary, 0);
    return result;
}

int pm3000_acme_store_write(const char *root, const char *name,
                            const unsigned char *data,
                            unsigned int data_length,
                            unsigned int mode)
{
    int root_fd = open_root(root);
    int result;
    if (root_fd < 0) return PM3000_ACME_STORE_UNSAFE;
    result = pm3000_acme_store_write_at(root_fd, name, data, data_length, mode);
    close(root_fd);
    return result;
}

int pm3000_acme_store_read_at(int root_fd, const char *name,
                              unsigned char *output,
                              unsigned int output_capacity,
                              unsigned int *output_length,
                              int require_private_mode)
{
    int file_fd = -1;
    struct pm3000_acme_stat info;
    unsigned int offset = 0U;
    int result = PM3000_ACME_STORE_IO;
    if (output_length != (unsigned int *)0) *output_length = 0U;
    if (!safe_name(name) || output == (unsigned char *)0 ||
        output_capacity == 0U || output_length == (unsigned int *)0)
        return PM3000_ACME_STORE_INVALID;
    if (!valid_root_fd(root_fd)) return PM3000_ACME_STORE_UNSAFE;
    file_fd = openat(root_fd, name, O_RDONLY | O_NOFOLLOW);
    if (file_fd < 0) goto done;
    if (pm3000_acme_fstat(file_fd, &info) != 0 ||
        !PM3000_ACME_S_ISREG(info.mode) || info.nlink != 1U ||
        info.uid != (unsigned long)geteuid() || info.size < 0 ||
        (unsigned long)info.size > STORE_FILE_MAX ||
        (unsigned long)info.size >= output_capacity ||
        (require_private_mode && (info.mode & 0777U) != 0600U)) {
        result = PM3000_ACME_STORE_UNSAFE;
        goto done;
    }
    while (offset < (unsigned int)info.size) {
        ssize_t amount = read(file_fd, output + offset,
                              (unsigned int)info.size - offset);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) goto done;
        offset += (unsigned int)amount;
    }
    output[offset] = '\0';
    *output_length = offset;
    result = PM3000_ACME_STORE_OK;
done:
    if (file_fd >= 0) close(file_fd);
    return result;
}

int pm3000_acme_store_read(const char *root, const char *name,
                           unsigned char *output,
                           unsigned int output_capacity,
                           unsigned int *output_length,
                           int require_private_mode)
{
    int root_fd = open_root(root);
    int result;
    if (root_fd < 0) return PM3000_ACME_STORE_UNSAFE;
    result = pm3000_acme_store_read_at(root_fd, name, output, output_capacity,
                                       output_length, require_private_mode);
    close(root_fd);
    return result;
}
