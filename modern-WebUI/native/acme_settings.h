#ifndef PM3000_ACME_SETTINGS_H
#define PM3000_ACME_SETTINGS_H

#include <stddef.h>

#define PM3000_ACME_DIRECTORY_CAPACITY 1292U
#define PM3000_ACME_CA_FILE_CAPACITY 1025U
#define PM3000_ACME_DNS_CAPACITY 254U
#define PM3000_ACME_DNS_LIMIT 16U

struct pm3000_acme_setting {
    int enabled;
    char directory_url[PM3000_ACME_DIRECTORY_CAPACITY];
    char ca_file[PM3000_ACME_CA_FILE_CAPACITY];
    unsigned int dns_name_count;
    char dns_names[PM3000_ACME_DNS_LIMIT][PM3000_ACME_DNS_CAPACITY];
};

struct pm3000_acme_renewal_status {
    char state[23];
    char phase[32];
    char reason[16];
    int has_diagnostic;
};

int pm3000_acme_parse_cli_config(const unsigned char *data, size_t length,
                                  struct pm3000_acme_setting *setting);
int pm3000_acme_parse_api_replacement(const unsigned char *data, size_t length,
                                      struct pm3000_acme_setting *setting);
int pm3000_acme_serialize_cli_config(const struct pm3000_acme_setting *setting,
                                     unsigned char *output, size_t capacity,
                                     size_t *length);
int pm3000_acme_parse_status(const unsigned char *data, size_t length,
                             struct pm3000_acme_renewal_status *status);
int pm3000_acme_setting_matches(const struct pm3000_acme_setting *left,
                                const struct pm3000_acme_setting *right,
                                int include_ca_file);
int pm3000_acme_valid_etag(const char *etag);
int pm3000_acme_is_managed_ca_file(const char *path);

#endif
