#ifndef PM3000_AVTRANS_H
#define PM3000_AVTRANS_H

#include <stddef.h>

int pm3000_fetch_topology(const char *socket_path, const char *credentials_path,
                          unsigned char **response, size_t *response_length,
                          char *error, unsigned int error_size);

#endif
