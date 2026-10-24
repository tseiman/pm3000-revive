#ifndef PM3000_ACME_URL_H
#define PM3000_ACME_URL_H

#define PM3000_ACME_HOST_MAX 253U
#define PM3000_ACME_PATH_MAX 1024U
#define PM3000_ACME_URL_TEXT_MAX (8U + PM3000_ACME_HOST_MAX + 6U + PM3000_ACME_PATH_MAX)

enum pm3000_acme_url_result {
    PM3000_ACME_URL_OK = 0,
    PM3000_ACME_URL_INVALID = -1
};

struct pm3000_acme_url {
    char host[PM3000_ACME_HOST_MAX + 1U];
    unsigned int port;
    char path[PM3000_ACME_PATH_MAX + 1U];
};

int pm3000_acme_dns_name_normalize(const char *input, char *output,
                                   unsigned int output_capacity);
int pm3000_acme_url_parse(const char *input, struct pm3000_acme_url *output);
int pm3000_acme_url_same_origin(const struct pm3000_acme_url *left,
                                const struct pm3000_acme_url *right);

#endif
