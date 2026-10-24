#ifndef PM3000_ACME_TLS_H
#define PM3000_ACME_TLS_H

#include "pm3000_acme_url.h"

enum pm3000_acme_tls_result {
    PM3000_ACME_TLS_OK = 0,
    PM3000_ACME_TLS_EOF = 1,
    PM3000_ACME_TLS_INVALID = -1,
    PM3000_ACME_TLS_NETWORK = -2,
    PM3000_ACME_TLS_TRUST = -3,
    PM3000_ACME_TLS_HOSTNAME = -4,
    PM3000_ACME_TLS_IO = -5
};

struct pm3000_acme_tls_connection {
    void *context;
    void *session;
    int socket_fd;
};

int pm3000_acme_tls_connect(const struct pm3000_acme_url *url,
                            const char *ca_file,
                            unsigned int timeout_seconds,
                            struct pm3000_acme_tls_connection *connection);
int pm3000_acme_tls_write_all(struct pm3000_acme_tls_connection *connection,
                              const unsigned char *data,
                              unsigned int length);
int pm3000_acme_tls_read(struct pm3000_acme_tls_connection *connection,
                         unsigned char *output, unsigned int capacity,
                         unsigned int *amount);
void pm3000_acme_tls_close(struct pm3000_acme_tls_connection *connection);
int pm3000_acme_tls_certificate_file_matches(const char *certificate_path,
                                              const char *hostname);

#endif
