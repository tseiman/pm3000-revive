/* Fixed-purpose ACME administration broker.
 * Installed setuid-root and executable only by the Apache daemon group.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PM3000_TESTING
#define PM3000_ACME_EXECUTABLE "/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme"
#else
#ifndef PM3000_TEST_EXECUTABLE
#error PM3000_TEST_EXECUTABLE must be a fixed compile-time path
#endif
#define PM3000_ACME_EXECUTABLE PM3000_TEST_EXECUTABLE
#endif

#define SOL_SOCKET_VALUE 1
/* Linux socket option numbers are architecture-specific. PPC uses 21. */
#define SO_PEERCRED_VALUE 21
#define REQUEST_HEADER_SIZE 12U
#define OUTPUT_LIMIT 8448U
#define CONFIG_LIMIT 8192U
#define CA_LIMIT 65536U
#define ETAG_LENGTH 66U
#define CONFIG_WIRE_LIMIT (ETAG_LENGTH + CONFIG_LIMIT)
#define CA_WIRE_LIMIT (ETAG_LENGTH + CA_LIMIT)

#define OP_CONFIG_SHOW 1U
#define OP_CONFIG_REPLACE 2U
#define OP_CA_INSTALL 3U
#define OP_STATUS 4U
#define OP_CONFIG_REVISION 5U
#define OP_RENEW_ASYNC 6U
#define OP_CONFIG_CREATE 7U
#define OP_CA_CREATE 8U
#define OP_BOOTSTRAP_STATUS 9U

#define RESPONSE_OK 0U
#define RESPONSE_BAD_REQUEST 1U
#define RESPONSE_EXEC_FAILED 2U
#define RESPONSE_CHILD_FAILED 3U
#define RESPONSE_OUTPUT_TOO_LARGE 4U
#define RESPONSE_BUSY 5U
#define RESPONSE_STARTUP_FAILED 6U
#define RESPONSE_OUTCOME_UNKNOWN 7U

struct peer_credentials {
    int pid;
    uid_t uid;
    gid_t gid;
};

static const unsigned char protocol_magic[4] = {'P', 'M', 'A', '1'};
static const char caller_user[] = "daemon";

static int write_all(int descriptor, const unsigned char *data, size_t length)
{
    while (length != 0U) {
        ssize_t amount = write(descriptor, data, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        data += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int read_exact(int descriptor, unsigned char *data, size_t length)
{
    while (length != 0U) {
        ssize_t amount = read(descriptor, data, length);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        data += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

static uint32_t decode_u32(const unsigned char *data)
{
    return ((uint32_t)data[0] << 24) | ((uint32_t)data[1] << 16) |
           ((uint32_t)data[2] << 8) | (uint32_t)data[3];
}

static void encode_u32(unsigned char *data, uint32_t value)
{
    data[0] = (unsigned char)(value >> 24);
    data[1] = (unsigned char)(value >> 16);
    data[2] = (unsigned char)(value >> 8);
    data[3] = (unsigned char)value;
}

static int send_response(unsigned int response, unsigned int child_status,
                         const unsigned char *output, size_t output_length)
{
    unsigned char header[REQUEST_HEADER_SIZE];
    memcpy(header, protocol_magic, sizeof(protocol_magic));
    header[4] = (unsigned char)response;
    header[5] = (unsigned char)child_status;
    header[6] = 0U;
    header[7] = 0U;
    encode_u32(header + 8U, (uint32_t)output_length);
    if (write_all(STDOUT_FILENO, header, sizeof(header)) != 0) return -1;
    return output_length == 0U ||
                   write_all(STDOUT_FILENO, output, output_length) == 0
               ? 0 : -1;
}

static int trusted_channel(int descriptor, int parent_pid, uid_t caller_uid)
{
    struct peer_credentials peer;
    struct stat status;
    socklen_t length = (socklen_t)sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    return fstat(descriptor, &status) == 0 && S_ISSOCK(status.st_mode) &&
           getsockopt(descriptor, SOL_SOCKET_VALUE, SO_PEERCRED_VALUE,
                      &peer, &length) == 0 &&
           length == (socklen_t)sizeof(peer) && peer.pid == parent_pid &&
           peer.uid == caller_uid;
}

static int same_channel(void)
{
    struct stat input_status;
    struct stat output_status;
    return fstat(STDIN_FILENO, &input_status) == 0 &&
           fstat(STDOUT_FILENO, &output_status) == 0 &&
           input_status.st_dev == output_status.st_dev &&
           input_status.st_ino == output_status.st_ino;
}

static void close_inherited_descriptors(void)
{
    long limit = sysconf(_SC_OPEN_MAX);
    int descriptor;
    if (limit < 3L || limit > 65536L) limit = 65536L;
    for (descriptor = 2; descriptor < (int)limit; ++descriptor)
        (void)close(descriptor);
}

static int request_shape(unsigned int opcode, uint32_t length,
                         char *arguments[7])
{
    arguments[0] = (char *)PM3000_ACME_EXECUTABLE;
    arguments[6] = NULL;
    if (opcode == OP_CONFIG_SHOW && length == 0U) {
        arguments[1] = (char *)"config";
        arguments[2] = (char *)"show";
        arguments[3] = NULL;
        return 1;
    }
    if (opcode == OP_CONFIG_REPLACE && length > ETAG_LENGTH &&
        length <= CONFIG_WIRE_LIMIT) {
        arguments[1] = (char *)"config";
        arguments[2] = (char *)"replace";
        arguments[3] = (char *)"--stdin";
        arguments[4] = (char *)"--if-match";
        return 1;
    }
    if (opcode == OP_CA_INSTALL && length > ETAG_LENGTH &&
        length <= CA_WIRE_LIMIT) {
        arguments[1] = (char *)"ca";
        arguments[2] = (char *)"install";
        arguments[3] = (char *)"--stdin";
        arguments[4] = (char *)"--if-match";
        return 1;
    }
    if (opcode == OP_STATUS && length == 0U) {
        arguments[1] = (char *)"status";
        arguments[2] = NULL;
        arguments[3] = NULL;
        return 1;
    }
    if (opcode == OP_CONFIG_REVISION && length == 0U) {
        arguments[1] = (char *)"config";
        arguments[2] = (char *)"revision";
        arguments[3] = NULL;
        return 1;
    }
    if (opcode == OP_RENEW_ASYNC && length == 0U) {
        arguments[1] = (char *)"renew";
        arguments[2] = (char *)"--foreground";
        arguments[3] = (char *)"--broker-startup-notify";
        arguments[4] = NULL;
        return 1;
    }
    if (opcode == OP_CONFIG_CREATE && length > 0U && length <= CONFIG_LIMIT) {
        arguments[1] = (char *)"config";
        arguments[2] = (char *)"replace";
        arguments[3] = (char *)"--stdin";
        arguments[4] = (char *)"--if-none-match";
        arguments[5] = (char *)"*";
        return 1;
    }
    if (opcode == OP_CA_CREATE && length > 0U && length <= CA_LIMIT) {
        arguments[1] = (char *)"ca";
        arguments[2] = (char *)"install";
        arguments[3] = (char *)"--stdin";
        arguments[4] = (char *)"--if-none-match";
        arguments[5] = (char *)"*";
        return 1;
    }
    if (opcode == OP_BOOTSTRAP_STATUS && length == 0U) {
        arguments[1] = (char *)"bootstrap";
        arguments[2] = (char *)"status";
        arguments[3] = NULL;
        return 1;
    }
    return 0;
}

static long long monotonic_milliseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (long long)value.tv_sec * 1000LL +
           (long long)value.tv_nsec / 1000000LL;
}

static int run_async_renew(char *const arguments[])
{
    int startup[2];
    pid_t child;
    char signal_byte;
    long long deadline;
    if (pipe(startup) != 0) return RESPONSE_EXEC_FAILED;
    child = fork();
    if (child < 0) {
        (void)close(startup[0]);
        (void)close(startup[1]);
        return RESPONSE_EXEC_FAILED;
    }
    if (child == 0) {
        int null_fd;
        long limit;
        int descriptor;
        char *const environment[] = {NULL};
        (void)close(startup[0]);
        null_fd = open("/dev/null", O_RDWR);
        if (null_fd < 0 || dup2(null_fd, STDIN_FILENO) < 0 ||
            dup2(null_fd, STDOUT_FILENO) < 0 ||
            dup2(null_fd, STDERR_FILENO) < 0 ||
            dup2(startup[1], 3) < 0)
            _exit(126);
        limit = sysconf(_SC_OPEN_MAX);
        if (limit < 4L || limit > 65536L) limit = 65536L;
        for (descriptor = 4; descriptor < (int)limit; ++descriptor)
            (void)close(descriptor);
        execve(PM3000_ACME_EXECUTABLE, arguments, environment);
        _exit(127);
    }
    (void)close(startup[1]);
    deadline = monotonic_milliseconds();
    if (deadline >= 0) deadline += 5000LL;
    for (;;) {
        struct pollfd item;
        long long now = monotonic_milliseconds();
        long long remaining;
        int result;
        ssize_t amount;
        if (deadline < 0 || now < 0 || now >= deadline) break;
        remaining = deadline - now;
        item.fd = startup[0];
        item.events = POLLIN;
        item.revents = 0;
        result = poll(&item, 1U, remaining > 2147483647LL ?
                                  2147483647 : (int)remaining);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) break;
        amount = read(startup[0], &signal_byte, 1U);
        if (amount < 0 && errno == EINTR) continue;
        if (amount == 1) {
            (void)close(startup[0]);
            if (signal_byte == 'A') return RESPONSE_OK;
            if (signal_byte == 'B') return RESPONSE_BUSY;
            if (signal_byte == 'F') return RESPONSE_STARTUP_FAILED;
            return RESPONSE_OUTCOME_UNKNOWN;
        }
        if (amount == 0) {
            (void)close(startup[0]);
            return RESPONSE_STARTUP_FAILED;
        }
        break;
    }
    (void)close(startup[0]);
    return RESPONSE_OUTCOME_UNKNOWN;
}

static int extract_etag(unsigned int opcode, const unsigned char *input,
                        uint32_t input_length, char etag[ETAG_LENGTH + 1U])
{
    size_t index;
    if (opcode != OP_CONFIG_REPLACE && opcode != OP_CA_INSTALL) return 1;
    if (input_length <= ETAG_LENGTH || input[0] != '"' ||
        input[ETAG_LENGTH - 1U] != '"')
        return 0;
    for (index = 1U; index + 1U < ETAG_LENGTH; ++index) {
        if (!((input[index] >= '0' && input[index] <= '9') ||
              (input[index] >= 'a' && input[index] <= 'f')))
            return 0;
    }
    memcpy(etag, input, ETAG_LENGTH);
    etag[ETAG_LENGTH] = '\0';
    return 1;
}

static int run_command(char *const arguments[], const unsigned char *input,
                       size_t input_length, unsigned char *output,
                       size_t *output_length, unsigned int *child_status)
{
    int input_pipe[2];
    int output_pipe[2];
    pid_t child;
    size_t total = 0U;
    int overflow = 0;
    int wait_status;
    char *const environment[] = {NULL};
    if (pipe(input_pipe) != 0) return RESPONSE_EXEC_FAILED;
    if (pipe(output_pipe) != 0) {
        (void)close(input_pipe[0]);
        (void)close(input_pipe[1]);
        return RESPONSE_EXEC_FAILED;
    }
    child = fork();
    if (child < 0) {
        (void)close(input_pipe[0]); (void)close(input_pipe[1]);
        (void)close(output_pipe[0]); (void)close(output_pipe[1]);
        return RESPONSE_EXEC_FAILED;
    }
    if (child == 0) {
        (void)close(input_pipe[1]);
        (void)close(output_pipe[0]);
        if (dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            dup2(output_pipe[1], STDOUT_FILENO) < 0)
            _exit(127);
        (void)close(input_pipe[0]);
        (void)close(output_pipe[1]);
        execve(PM3000_ACME_EXECUTABLE, arguments, environment);
        _exit(127);
    }
    (void)close(input_pipe[0]);
    (void)close(output_pipe[1]);
    if (input_length != 0U &&
        write_all(input_pipe[1], input, input_length) != 0) {
        (void)kill(child, SIGKILL);
    }
    (void)close(input_pipe[1]);
    for (;;) {
        unsigned char discard[512];
        unsigned char *destination = total < OUTPUT_LIMIT ? output + total : discard;
        size_t capacity = total < OUTPUT_LIMIT ? OUTPUT_LIMIT - total : sizeof(discard);
        ssize_t amount = read(output_pipe[0], destination, capacity);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) overflow = 1;
        if (amount <= 0) break;
        if (total < OUTPUT_LIMIT) total += (size_t)amount;
        else overflow = 1;
        if (total == OUTPUT_LIMIT) {
            unsigned char probe;
            amount = read(output_pipe[0], &probe, 1U);
            if (amount > 0) overflow = 1;
            if (amount <= 0) break;
        }
    }
    (void)close(output_pipe[0]);
    while (waitpid(child, &wait_status, 0) < 0) {
        if (errno != EINTR) return RESPONSE_EXEC_FAILED;
    }
    *output_length = total;
    if (WIFEXITED(wait_status)) *child_status = (unsigned int)WEXITSTATUS(wait_status);
    else if (WIFSIGNALED(wait_status)) *child_status = 128U + (unsigned int)WTERMSIG(wait_status);
    else *child_status = 255U;
    if (overflow) {
        *output_length = 0U;
        return RESPONSE_OUTPUT_TOO_LARGE;
    }
    if (*child_status == 127U) {
        *output_length = 0U;
        return RESPONSE_EXEC_FAILED;
    }
    return *child_status == 0U ? RESPONSE_OK : RESPONSE_CHILD_FAILED;
}

int main(int argc, char **argv)
{
    unsigned char header[REQUEST_HEADER_SIZE];
    unsigned char input[CA_WIRE_LIMIT];
    unsigned char output[OUTPUT_LIMIT];
    struct passwd *caller;
    uid_t caller_uid;
    int parent_pid;
    uint32_t input_length;
    unsigned int opcode;
    unsigned int child_status = 255U;
    size_t output_length = 0U;
    int response;
    char etag[ETAG_LENGTH + 1U];
    char *arguments[7] = {NULL, NULL, NULL, NULL, NULL, NULL, NULL};
    (void)argv;
    (void)signal(SIGPIPE, SIG_IGN);
    parent_pid = (int)getppid();
    caller_uid = getuid();
    caller = getpwnam(caller_user);
    if (argc != 1 || geteuid() != 0U || caller == NULL ||
        caller_uid != caller->pw_uid ||
        !trusted_channel(STDIN_FILENO, parent_pid, caller_uid) ||
        !trusted_channel(STDOUT_FILENO, parent_pid, caller_uid) ||
        !same_channel())
        return 2;
    close_inherited_descriptors();
    if (read_exact(STDIN_FILENO, header, sizeof(header)) != 0 ||
        memcmp(header, protocol_magic, sizeof(protocol_magic)) != 0 ||
        header[5] != 0U || header[6] != 0U || header[7] != 0U) {
        (void)send_response(RESPONSE_BAD_REQUEST, 255U, NULL, 0U);
        return 3;
    }
    opcode = header[4];
    input_length = decode_u32(header + 8U);
    if (!request_shape(opcode, input_length, arguments)) {
        (void)send_response(RESPONSE_BAD_REQUEST, 255U, NULL, 0U);
        return 3;
    }
    if (input_length != 0U &&
        read_exact(STDIN_FILENO, input, input_length) != 0) {
        (void)send_response(RESPONSE_BAD_REQUEST, 255U, NULL, 0U);
        return 3;
    }
    if (!extract_etag(opcode, input, input_length, etag)) {
        (void)send_response(RESPONSE_BAD_REQUEST, 255U, NULL, 0U);
        return 3;
    }
    if (opcode == OP_CONFIG_REPLACE || opcode == OP_CA_INSTALL) {
        arguments[5] = etag;
        input_length -= ETAG_LENGTH;
        memmove(input, input + ETAG_LENGTH, input_length);
    }
    if (opcode == OP_RENEW_ASYNC) {
        response = run_async_renew(arguments);
        child_status = response == RESPONSE_OK ? 0U : 255U;
    } else {
        response = run_command(arguments, input, input_length, output,
                               &output_length, &child_status);
    }
    if (send_response((unsigned int)response, child_status,
                      output, output_length) != 0)
        return 4;
    return response == RESPONSE_OK ? 0 : 5;
}
