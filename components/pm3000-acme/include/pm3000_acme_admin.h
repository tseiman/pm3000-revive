#ifndef PM3000_ACME_ADMIN_H
#define PM3000_ACME_ADMIN_H

#include "pm3000_acme_config.h"

#define PM3000_ACME_ADMIN_OUTPUT_MAX (PM3000_ACME_CONFIG_MAX_BYTES + 256U)
#define PM3000_ACME_ADMIN_ETAG_BYTES 67U

enum pm3000_acme_admin_result {
    PM3000_ACME_ADMIN_OK = 0,
    PM3000_ACME_ADMIN_INVALID = -1,
    PM3000_ACME_ADMIN_IO = -2,
    PM3000_ACME_ADMIN_UNSAFE = -3,
    PM3000_ACME_ADMIN_BUSY = -4,
    PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN = -5,
    PM3000_ACME_ADMIN_STALE = -6,
    PM3000_ACME_ADMIN_NOT_FOUND = -7
};

int pm3000_acme_admin_config_show(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length);
int pm3000_acme_admin_config_revision(
    const char *root, const char *managed_path,
    char *output, unsigned int output_capacity);
int pm3000_acme_admin_config_replace(
    const char *root, const unsigned char *input, unsigned int input_length);
int pm3000_acme_admin_config_replace_if_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length,
    const char *expected_revision);
int pm3000_acme_admin_config_create_if_none_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length);
int pm3000_acme_admin_ca_install(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length);
int pm3000_acme_admin_ca_install_if_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length,
    const char *expected_revision);
int pm3000_acme_admin_ca_create_if_none_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length);
int pm3000_acme_admin_bootstrap_status(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length);
int pm3000_acme_admin_status(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length);
int pm3000_acme_admin_status_write(const char *root, const char *state);
int pm3000_acme_admin_status_write_at(int root_fd, const char *state);
int pm3000_acme_admin_status_write_failure(
    const char *root, const char *phase, const char *reason);
int pm3000_acme_admin_status_write_failure_at(
    int root_fd, const char *phase, const char *reason);

#endif
