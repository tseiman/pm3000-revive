#define _GNU_SOURCE

#ifdef PM3000_FIRMWARE_ABI
#include <asm/unistd.h>
#include <fcntl.h>
#include <stdarg.h>
#include <sys/types.h>

extern long syscall(long number, ...);

int openat(int directory, const char *path, int flags, ...)
{
    mode_t mode = 0;
    if ((flags & O_CREAT) != 0) {
        va_list arguments;
        va_start(arguments, flags);
        mode = (mode_t)va_arg(arguments, int);
        va_end(arguments);
    }
    return (int)syscall(__NR_openat, directory, path, flags, mode);
}

int renameat(int old_directory, const char *old_path,
             int new_directory, const char *new_path)
{
    return (int)syscall(__NR_renameat, old_directory, old_path,
                        new_directory, new_path);
}

int unlinkat(int directory, const char *path, int flags)
{
    return (int)syscall(__NR_unlinkat, directory, path, flags);
}
#else
int pm3000_acme_syscall_compat_host_translation_unit;
#endif
