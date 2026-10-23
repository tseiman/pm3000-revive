#define _POSIX_C_SOURCE 200809L

#include "avtrans.h"

#include <errno.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <unistd.h>

ssize_t __real_send(int descriptor, const void *buffer, size_t length, int flags);

static int fault_mode;
static int send_calls;

ssize_t __wrap_send(int descriptor, const void *buffer, size_t length, int flags) {
    ++send_calls;
    if (fault_mode == 1 && send_calls == 2 && length > 1U)
        return __real_send(descriptor, buffer, 1U, flags);
    if (fault_mode == 2 && length == 1U && ((const unsigned char *)buffer)[0] == 0U) {
        errno = EPIPE;
        return -1;
    }
    return __real_send(descriptor, buffer, length, flags);
}

static int serve_once(int listener) {
    int connection = accept(listener, NULL, NULL);
    unsigned char buffer[512];
    ssize_t amount;
    int found_nul = 0;
    size_t received = 0U;
    if (connection < 0) return 10;
    while ((amount = read(connection, buffer, sizeof(buffer))) > 0) {
        size_t index;
        for (index = 0U; index < (size_t)amount; ++index) {
            if (received + index >= 59U && buffer[index] == 0U) {
                found_nul = 1;
                break;
            }
        }
        received += (size_t)amount;
        if (found_nul) break;
    }
    close(connection);
    return found_nul ? 0 : 11;
}

int main(int argc, char **argv) {
    struct sockaddr_un address;
    char socket_path[sizeof(address.sun_path)];
    char error[160];
    int listener;
    int result;
    int status;
    pid_t child;

    if (argc != 2 || (strcmp(argv[1], "short") != 0 && strcmp(argv[1], "terminator") != 0))
        return 2;
    fault_mode = strcmp(argv[1], "short") == 0 ? 1 : 2;
    if (snprintf(socket_path, sizeof(socket_path), "/tmp/pm3000-avtrans-fault-%ld.sock", (long)getpid()) >= (int)sizeof(socket_path))
        return 3;
    listener = socket(AF_UNIX, SOCK_STREAM, 0);
    if (listener < 0) return 4;
    memset(&address, 0, sizeof(address));
    address.sun_family = AF_UNIX;
    strcpy(address.sun_path, socket_path);
    unlink(socket_path);
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 || listen(listener, 1) != 0)
        return 5;
    child = fork();
    if (child < 0) return 6;
    if (child == 0) _exit(serve_once(listener));

    setenv("REMOTE_ADDR", "127.0.0.1", 1);
    error[0] = '\0';
    result = pm3000_save_dsview_setting_session(socket_path, "test-service-sid", 1, error, sizeof(error));
    close(listener);
    unlink(socket_path);
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status)) return 7;
    printf("mode=%s result=%d child=%d error=%s\n", argv[1], result, WEXITSTATUS(status), error);
    return result == 3 && WEXITSTATUS(status) == (fault_mode == 1 ? 0 : 11) ? 0 : 1;
}
