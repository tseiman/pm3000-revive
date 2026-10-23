#ifndef PM3000_SERVICE_SESSION_H
#define PM3000_SERVICE_SESSION_H

#include <sys/types.h>

#define PM3000_SERVICE_SID_SIZE 129U

struct pm3000_service_session {
    char sid[PM3000_SERVICE_SID_SIZE];
    int control_fd;
    pid_t helper_pid;
};

/* Returns 0 on success, 1 when pm3000-rest is absent, and -1 otherwise. */
int pm3000_service_session_open(const char *helper_path,
                                struct pm3000_service_session *session,
                                char *error, unsigned int error_size);
/* Returns 0 only when the helper confirms successful session destruction. */
int pm3000_service_session_close(struct pm3000_service_session *session);

#endif
