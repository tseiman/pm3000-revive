#ifndef PM3000_ACME_CONFIG_H
#define PM3000_ACME_CONFIG_H

#include "pm3000_acme_protocol.h"

#define PM3000_ACME_CA_PATH_MAX 1024U

enum pm3000_acme_config_result {
    PM3000_ACME_CONFIG_OK = 0,
    PM3000_ACME_CONFIG_INVALID = -1,
    PM3000_ACME_CONFIG_LIMIT = -2
};

struct pm3000_acme_runtime_config {
    int enabled;
    char directory_url[PM3000_ACME_URL_TEXT_MAX + 1U];
    char ca_file[PM3000_ACME_CA_PATH_MAX + 1U];
    unsigned int dns_name_count;
    char dns_names[PM3000_ACME_MAX_IDENTIFIERS]
                  [PM3000_ACME_HOST_MAX + 1U];
};

int pm3000_acme_config_parse(const unsigned char *json,
                             unsigned int json_length,
                             struct pm3000_acme_runtime_config *config);

#endif
