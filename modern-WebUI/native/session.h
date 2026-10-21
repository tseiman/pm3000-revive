#ifndef PM3000_SESSION_H
#define PM3000_SESSION_H

#include <stddef.h>
#include <stdint.h>
#include <stdio.h>

#define PM3000_SESSION_ID_LENGTH 43U
#define PM3000_CSRF_LENGTH 43U
#define PM3000_SESSION_PATH_COUNT 58U

typedef struct {
    char id[PM3000_SESSION_ID_LENGTH + 1U];
    char csrf[PM3000_CSRF_LENGTH + 1U];
    char sid[129];
    char username[129];
    uint64_t path_mask;
    int can_manage_tokens;
    int can_control_power;
    int can_help_language;
    int can_data_buffering;
} pm3000_session;

int pm3000_session_create(const char *directory, const char *username,
                          const char *sid, const unsigned char *navigation,
                          size_t navigation_length, const unsigned char *topology,
                          size_t topology_length, pm3000_session *session,
                          char *error, unsigned int error_size);
int pm3000_session_load(const char *directory, const char *identifier,
                        int refresh, pm3000_session *session,
                        char *error, unsigned int error_size);
int pm3000_session_delete(const char *directory, const char *identifier,
                          char *error, unsigned int error_size);
int pm3000_session_csrf_matches(const pm3000_session *session, const char *value);
int pm3000_session_has_path(const pm3000_session *session, const char *path);
int pm3000_session_write_json(FILE *output, const pm3000_session *session);

#endif
