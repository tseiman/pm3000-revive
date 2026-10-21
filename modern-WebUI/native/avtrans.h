#ifndef PM3000_AVTRANS_H
#define PM3000_AVTRANS_H

#include <stddef.h>

int pm3000_fetch_topology(const char *socket_path, const char *credentials_path,
                          unsigned char **response, size_t *response_length,
                          char *error, unsigned int error_size);
int pm3000_fetch_pdus(const char *socket_path, const char *credentials_path,
                      unsigned char **response, size_t *response_length,
                      char *error, unsigned int error_size);
int pm3000_apply_outlet_action(const char *socket_path, const char *credentials_path,
                               const char *outlet_id, const char *revision,
                               const char *action, char *error,
                               unsigned int error_size);
int pm3000_apply_pdu_action(const char *socket_path, const char *credentials_path,
                            const char *pdu_id, const char *revision,
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
int pm3000_fetch_pdus_session(const char *socket_path, const char *sid,
                              unsigned char **response, size_t *response_length,
                              char *error, unsigned int error_size);
int pm3000_apply_outlet_action_session(const char *socket_path, const char *sid,
                                       const char *outlet_id, const char *revision,
                                       const char *action, char *error,
                                       unsigned int error_size);
int pm3000_apply_pdu_action_session(const char *socket_path, const char *sid,
                                    const char *pdu_id, const char *revision,
                                    const char *action, char *error,
                                    unsigned int error_size);
int pm3000_change_password_session(const char *socket_path, const char *sid,
                                   const char *old_password,
                                   const char *new_password,
                                   const char *confirmation,
                                   char *error, unsigned int error_size);
int pm3000_fetch_dsview_setting_session(const char *socket_path, const char *sid,
                                        unsigned char **response,
                                        size_t *response_length, char *error,
                                        unsigned int error_size);
int pm3000_save_dsview_setting_session(const char *socket_path, const char *sid,
                                       int allow_dsview, char *error,
                                       unsigned int error_size);
int pm3000_fetch_nis_setting_session(const char *socket_path, const char *sid,
                                     unsigned char **response,
                                     size_t *response_length, char *error,
                                     unsigned int error_size);
int pm3000_save_nis_setting_session(const char *socket_path, const char *sid,
                                    const char *domain_name,
                                    const char *address, char *error,
                                    unsigned int error_size);
int pm3000_fetch_sysinfo_session(const char *socket_path, const char *sid,
                                  unsigned char **response,
                                  size_t *response_length, char *error,
                                  unsigned int error_size);
int pm3000_fetch_memory_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size);
int pm3000_fetch_flash_session(const char *socket_path, const char *sid,
                                unsigned char **response,
                                size_t *response_length, char *error,
                                unsigned int error_size);
int pm3000_fetch_netdev_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size);
int pm3000_fetch_route4_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size);
int pm3000_fetch_route6_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size);
int pm3000_fetch_serial_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size);
int pm3000_fetch_fixed_setting_session(const char *socket_path, const char *sid,
                                        const char *path,
                                        unsigned char **response,
                                        size_t *response_length, char *error,
                                        unsigned int error_size);
int pm3000_save_fixed_setting_session(const char *socket_path, const char *sid,
                                       const char *path, const char *form_payload,
                                       unsigned char **response,
                                       size_t *response_length, char *error,
                                       unsigned int error_size);

#endif
