#ifndef PM3000_AVTRANS_H
#define PM3000_AVTRANS_H

#include <stddef.h>

int pm3000_fetch_topology(const char *socket_path, const char *credentials_path,
                          unsigned char **response, size_t *response_length,
                          char *error, unsigned int error_size);
int pm3000_apply_outlet_action(const char *socket_path, const char *credentials_path,
                               const char *outlet_id, const char *revision,
                               const char *action, char *error,
                               unsigned int error_size);
int pm3000_login_session(const char *socket_path, const char *username,
                         const char *password, char sid[129],
                         unsigned char **navigation, size_t *navigation_length,
                         char *error, unsigned int error_size);
int pm3000_logout_session(const char *socket_path, const char *sid,
                          char *error, unsigned int error_size);
int pm3000_fetch_topology_session(const char *socket_path, const char *sid,
                                  unsigned char **response, size_t *response_length,
                                  char *error, unsigned int error_size);
int pm3000_apply_outlet_action_session(const char *socket_path, const char *sid,
                                       const char *outlet_id, const char *revision,
                                       const char *action, char *error,
                                       unsigned int error_size);

#endif
