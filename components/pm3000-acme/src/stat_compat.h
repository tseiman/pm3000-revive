#ifndef PM3000_ACME_STAT_COMPAT_H
#define PM3000_ACME_STAT_COMPAT_H

struct pm3000_acme_stat {
    unsigned long mode;
    unsigned long nlink;
    unsigned long uid;
    long long size;
};

#define PM3000_ACME_S_IFMT  0170000UL
#define PM3000_ACME_S_IFDIR 0040000UL
#define PM3000_ACME_S_IFREG 0100000UL
#define PM3000_ACME_S_ISDIR(m) \
    (((unsigned long)(m) & PM3000_ACME_S_IFMT) == PM3000_ACME_S_IFDIR)
#define PM3000_ACME_S_ISREG(m) \
    (((unsigned long)(m) & PM3000_ACME_S_IFMT) == PM3000_ACME_S_IFREG)

int pm3000_acme_fstat(int descriptor, struct pm3000_acme_stat *output);
int pm3000_acme_lstat(const char *path, struct pm3000_acme_stat *output);

#endif
