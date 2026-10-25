#define _POSIX_C_SOURCE 200809L

#include "stat_compat.h"

#ifdef PM3000_FIRMWARE_ABI
#include <asm/stat.h>
#include <asm/unistd.h>

extern long syscall(long number, ...);

static void copy_stat64(const struct stat64 *input,
                        struct pm3000_acme_stat *output)
{
    output->mode = input->st_mode;
    output->nlink = input->st_nlink;
    output->uid = input->st_uid;
    output->size = input->st_size;
}

int pm3000_acme_fstat(int descriptor, struct pm3000_acme_stat *output)
{
    struct stat64 status;
    if (output == (struct pm3000_acme_stat *)0 ||
        syscall(__NR_fstat64, descriptor, &status) != 0L) return -1;
    copy_stat64(&status, output);
    return 0;
}

int pm3000_acme_lstat(const char *path, struct pm3000_acme_stat *output)
{
    struct stat64 status;
    if (path == (const char *)0 || output == (struct pm3000_acme_stat *)0 ||
        syscall(__NR_lstat64, path, &status) != 0L) return -1;
    copy_stat64(&status, output);
    return 0;
}
#else
#include <sys/stat.h>

static void copy_stat(const struct stat *input,
                      struct pm3000_acme_stat *output)
{
    output->mode = (unsigned long)input->st_mode;
    output->nlink = (unsigned long)input->st_nlink;
    output->uid = (unsigned long)input->st_uid;
    output->size = (long long)input->st_size;
}

int pm3000_acme_fstat(int descriptor, struct pm3000_acme_stat *output)
{
    struct stat status;
    if (output == (struct pm3000_acme_stat *)0 ||
        fstat(descriptor, &status) != 0) return -1;
    copy_stat(&status, output);
    return 0;
}

int pm3000_acme_lstat(const char *path, struct pm3000_acme_stat *output)
{
    struct stat status;
    if (path == (const char *)0 || output == (struct pm3000_acme_stat *)0 ||
        lstat(path, &status) != 0) return -1;
    copy_stat(&status, output);
    return 0;
}
#endif
