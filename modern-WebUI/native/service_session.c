#define _POSIX_C_SOURCE 200112L
#include "service_session.h"

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#define HELPER_LINE_SIZE 160U

static void set_error(char *error, unsigned int error_size, const char *message) {
    if (error == NULL || error_size == 0U) return;
    (void)snprintf(error, error_size, "%s", message);
}

static void wipe(void *pointer, unsigned int length) {
    volatile unsigned char *bytes = (volatile unsigned char *)pointer;
    while (length > 0U) {
        *bytes++ = 0U;
        --length;
    }
}

static int cloexec_socketpair(int descriptors[2]) {
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, descriptors) != 0) return -1;
    if (fcntl(descriptors[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(descriptors[1], F_SETFD, FD_CLOEXEC) != 0) {
        close(descriptors[0]);
        close(descriptors[1]);
        return -1;
    }
    return 0;
}

static int valid_sid(const char *sid) {
    unsigned int index = 0U;
    unsigned char value;
    while ((value = (unsigned char)sid[index]) != 0U) {
        if (index >= PM3000_SERVICE_SID_SIZE - 1U ||
            !((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '_' || value == '-'))
            return 0;
        ++index;
    }
    return index > 0U;
}

static int read_line(int descriptor, char *line, unsigned int size) {
    unsigned int used = 0U;
    while (used + 1U < size) {
        char value;
        ssize_t amount = read(descriptor, &value, 1U);
        if (amount != 1) return -1;
        if (value == '\n') {
            line[used] = '\0';
            return 0;
        }
        if (value == '\0' || value == '\r') return -1;
        line[used++] = value;
    }
    return -1;
}

static pid_t bounded_wait(pid_t child, int *status, unsigned int attempts) {
    struct timespec pause;
    pause.tv_sec = 0;
    pause.tv_nsec = 100000000L;
    while (attempts-- > 0U) {
        pid_t result;
        do {
            result = waitpid(child, status, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result != 0) return result;
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) { }
        pause.tv_sec = 0;
        pause.tv_nsec = 100000000L;
    }
    return 0;
}

int pm3000_service_session_close(struct pm3000_service_session *session) {
    int status = 0;
    pid_t result;
    int cleanup_result = 0;
    if (session == NULL) return -1;
    if (session->control_fd >= 0) {
        if (close(session->control_fd) != 0) cleanup_result = -1;
        session->control_fd = -1;
    }
    if (session->helper_pid > 0) {
        result = bounded_wait(session->helper_pid, &status, 50U);
        if (result == 0) {
            (void)kill(session->helper_pid, SIGTERM);
            result = bounded_wait(session->helper_pid, &status, 20U);
        }
        if (result == 0) {
            (void)kill(session->helper_pid, SIGKILL);
            result = bounded_wait(session->helper_pid, &status, 20U);
        }
        if (result != session->helper_pid || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
            cleanup_result = -1;
        session->helper_pid = -1;
    }
    wipe(session->sid, sizeof(session->sid));
    return cleanup_result;
}

int pm3000_service_session_open(const char *helper_path,
                                struct pm3000_service_session *session,
                                char *error, unsigned int error_size) {
    int channel[2] = {-1, -1};
    char line[HELPER_LINE_SIZE];
    pid_t child;
    int result = -1;
    if (session == NULL || helper_path == NULL || helper_path[0] != '/') {
        set_error(error, error_size, "service session helper path invalid");
        return -1;
    }
    memset(session, 0, sizeof(*session));
    session->control_fd = -1;
    session->helper_pid = -1;
    if (cloexec_socketpair(channel) != 0) {
        set_error(error, error_size, "service session channel unavailable");
        goto done;
    }
    child = fork();
    if (child < 0) {
        set_error(error, error_size, "service session helper unavailable");
        goto done;
    }
    if (child == 0) {
        char *const arguments[] = {(char *)helper_path, NULL};
        char *const environment[] = {NULL};
        close(channel[0]);
        if (dup2(channel[1], STDIN_FILENO) < 0 ||
            dup2(channel[1], STDOUT_FILENO) < 0)
            _exit(126);
        if (channel[1] != STDIN_FILENO && channel[1] != STDOUT_FILENO)
            close(channel[1]);
        execve(helper_path, arguments, environment);
        {
            static const char unavailable[] = "ERR HELPER_UNAVAILABLE\n";
            (void)write(STDOUT_FILENO, unavailable, sizeof(unavailable) - 1U);
        }
        _exit(127);
    }
    close(channel[1]);
    channel[1] = -1;
    session->helper_pid = child;
    {
        struct timeval timeout;
        timeout.tv_sec = 10;
        timeout.tv_usec = 0;
        if (setsockopt(channel[0], SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) != 0) {
            set_error(error, error_size, "service session timeout unavailable");
            goto done;
        }
    }
    if (read_line(channel[0], line, sizeof(line)) != 0) {
        set_error(error, error_size, "service session helper rejected");
        goto done;
    }
    if (strcmp(line, "ERR USER_MISSING") == 0) {
        set_error(error, error_size, "service identity missing");
        result = 1;
        goto done;
    }
    if (strncmp(line, "OK ", 3U) != 0 || !valid_sid(line + 3U)) {
        set_error(error, error_size, "service session helper rejected");
        goto done;
    }
    memcpy(session->sid, line + 3U, strlen(line + 3U) + 1U);
    session->control_fd = channel[0];
    channel[0] = -1;
    result = 0;
done:
    wipe(line, sizeof(line));
    if (channel[0] >= 0) close(channel[0]);
    if (channel[1] >= 0) close(channel[1]);
    if (result != 0) (void)pm3000_service_session_close(session);
    return result;
}
