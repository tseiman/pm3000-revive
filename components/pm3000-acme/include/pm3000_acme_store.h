#ifndef PM3000_ACME_STORE_H
#define PM3000_ACME_STORE_H

enum pm3000_acme_store_result {
    PM3000_ACME_STORE_OK = 0,
    PM3000_ACME_STORE_INVALID = -1,
    PM3000_ACME_STORE_IO = -2,
    PM3000_ACME_STORE_LIMIT = -3,
    PM3000_ACME_STORE_UNSAFE = -4
};

int pm3000_acme_store_write(const char *root, const char *name,
                            const unsigned char *data,
                            unsigned int data_length,
                            unsigned int mode);
int pm3000_acme_store_read(const char *root, const char *name,
                           unsigned char *output,
                           unsigned int output_capacity,
                           unsigned int *output_length,
                           int require_private_mode);

#endif
