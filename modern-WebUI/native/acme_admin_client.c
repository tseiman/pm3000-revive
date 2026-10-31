#define _POSIX_C_SOURCE 200809L
#include "acme_admin_client.h"

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <signal.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#ifndef PM3000_ACME_ADMIN_TIMEOUT_MS
#define PM3000_ACME_ADMIN_TIMEOUT_MS 10000
#endif

#define FRAME_SIZE 12U
#define RESPONSE_OK 0U
#define RESPONSE_BAD_REQUEST 1U
#define RESPONSE_EXEC_FAILED 2U
#define RESPONSE_CHILD_FAILED 3U
#define RESPONSE_OUTPUT_TOO_LARGE 4U
#define RESPONSE_BUSY 5U
#define RESPONSE_STARTUP_FAILED 6U
#define RESPONSE_OUTCOME_UNKNOWN 7U

static const unsigned char protocol_magic[4] = {'P', 'M', 'A', '1'};

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

static int valid_request(unsigned int opcode, const unsigned char *body,
                         size_t body_length, const char *revision)
{
    size_t index;
    if (body_length != 0U && body == NULL) return 0;
    if (opcode == PM3000_ACME_ADMIN_CONFIG_SHOW ||
        opcode == PM3000_ACME_ADMIN_STATUS ||
        opcode == PM3000_ACME_ADMIN_CONFIG_REVISION ||
        opcode == PM3000_ACME_ADMIN_RENEW_ASYNC ||
        opcode == PM3000_ACME_ADMIN_BOOTSTRAP_STATUS)
        return revision == NULL && body_length == 0U;
    if (opcode == PM3000_ACME_ADMIN_CONFIG_CREATE)
        return revision == NULL && body_length > 0U &&
               body_length <= PM3000_ACME_ADMIN_CONFIG_LIMIT;
    if (opcode == PM3000_ACME_ADMIN_CA_CREATE)
        return revision == NULL && body_length > 0U &&
               body_length <= PM3000_ACME_ADMIN_CA_LIMIT;
    if (revision == NULL || strlen(revision) != PM3000_ACME_ADMIN_ETAG_LENGTH ||
        revision[0] != '"' || revision[PM3000_ACME_ADMIN_ETAG_LENGTH - 1U] != '"')
        return 0;
    for (index = 1U; index + 1U < PM3000_ACME_ADMIN_ETAG_LENGTH; ++index) {
        if (!((revision[index] >= '0' && revision[index] <= '9') ||
              (revision[index] >= 'a' && revision[index] <= 'f')))
            return 0;
    }
    if (opcode == PM3000_ACME_ADMIN_CONFIG_REPLACE)
        return body_length > 0U && body_length <= PM3000_ACME_ADMIN_CONFIG_LIMIT;
    if (opcode == PM3000_ACME_ADMIN_CA_INSTALL)
        return body_length > 0U && body_length <= PM3000_ACME_ADMIN_CA_LIMIT;
    return 0;
}

static int is_mutation(unsigned int opcode)
{
    return opcode == PM3000_ACME_ADMIN_CONFIG_REPLACE ||
           opcode == PM3000_ACME_ADMIN_CA_INSTALL ||
           opcode == PM3000_ACME_ADMIN_RENEW_ASYNC ||
           opcode == PM3000_ACME_ADMIN_CONFIG_CREATE ||
           opcode == PM3000_ACME_ADMIN_CA_CREATE;
}

static long long monotonic_milliseconds(void)
{
    struct timespec value;
    if (clock_gettime(CLOCK_MONOTONIC, &value) != 0) return -1;
    return (long long)value.tv_sec * 1000LL + (long long)value.tv_nsec / 1000000LL;
}

static int wait_ready(int descriptor, short events, long long deadline)
{
    struct pollfd item;
    for (;;) {
        long long now = monotonic_milliseconds();
        long long remaining;
        int timeout;
        int result;
        if (now < 0 || now >= deadline) return -1;
        remaining = deadline - now;
        timeout = remaining > 2147483647LL ? 2147483647 : (int)remaining;
        item.fd = descriptor;
        item.events = events;
        item.revents = 0;
        result = poll(&item, 1U, timeout);
        if (result < 0 && errno == EINTR) continue;
        if (result <= 0) return -1;
        if ((item.revents & (events | POLLHUP | POLLERR | POLLNVAL)) != 0)
            return 0;
    }
}

static int send_all(int descriptor, const unsigned char *data, size_t length,
                    long long deadline)
{
    while (length != 0U) {
        ssize_t amount;
        if (wait_ready(descriptor, POLLOUT, deadline) != 0) return -1;
#ifdef MSG_NOSIGNAL
        amount = send(descriptor, data, length, MSG_NOSIGNAL);
#else
        amount = send(descriptor, data, length, 0);
#endif
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (amount <= 0) return -1;
        data += (size_t)amount;
        length -= (size_t)amount;
    }
    return 0;
}

/* Returns 0 on success, 1 on clean EOF before any requested byte, -1 otherwise. */
static int receive_exact(int descriptor, unsigned char *data, size_t length,
                         long long deadline)
{
    size_t received = 0U;
    while (received < length) {
        ssize_t amount;
        if (wait_ready(descriptor, POLLIN, deadline) != 0) return -1;
        amount = recv(descriptor, data + received, length - received, 0);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        if (amount == 0) return received == 0U ? 1 : -1;
        if (amount < 0) return -1;
        received += (size_t)amount;
    }
    return 0;
}

static int expect_eof(int descriptor, long long deadline)
{
    unsigned char extra;
    for (;;) {
        ssize_t amount;
        if (wait_ready(descriptor, POLLIN, deadline) != 0) return -1;
        amount = recv(descriptor, &extra, 1U, 0);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) continue;
        return amount == 0 ? 0 : 1;
    }
}

static pid_t wait_briefly(pid_t child, int *status, unsigned int milliseconds)
{
    struct timespec pause;
    unsigned int elapsed = 0U;
    pause.tv_sec = 0;
    pause.tv_nsec = 10000000L;
    while (elapsed <= milliseconds) {
        pid_t result;
        do {
            result = waitpid(child, status, WNOHANG);
        } while (result < 0 && errno == EINTR);
        if (result != 0) return result;
        if (elapsed == milliseconds) break;
        while (nanosleep(&pause, &pause) != 0 && errno == EINTR) { }
        pause.tv_sec = 0;
        pause.tv_nsec = 10000000L;
        elapsed += 10U;
        if (elapsed > milliseconds) elapsed = milliseconds;
    }
    return 0;
}

static int terminate_and_reap(pid_t child, int *status)
{
    pid_t result = wait_briefly(child, status, 20U);
    if (result == 0) {
        (void)kill(child, SIGTERM);
        result = wait_briefly(child, status, 50U);
    }
    if (result == 0) {
        (void)kill(child, SIGKILL);
        do {
            result = waitpid(child, status, 0);
        } while (result < 0 && errno == EINTR);
    }
    return result == child ? 0 : -1;
}

static void close_inherited_descriptors(void)
{
    long limit = sysconf(_SC_OPEN_MAX);
    int descriptor;
    if (limit < 3L || limit > 65536L) limit = 65536L;
    for (descriptor = 2; descriptor < (int)limit; ++descriptor)
        (void)close(descriptor);
}

static int response_is_consistent(unsigned int code, unsigned int child_status,
                                  size_t output_length)
{
    if (code == RESPONSE_OK)
        return child_status == 0U;
    if (code == RESPONSE_BAD_REQUEST || code == RESPONSE_EXEC_FAILED)
        return child_status == 255U && output_length == 0U;
    if (code == RESPONSE_CHILD_FAILED)
        return child_status != 0U;
    if (code == RESPONSE_OUTPUT_TOO_LARGE)
        return output_length == 0U;
    if (code == RESPONSE_BUSY || code == RESPONSE_STARTUP_FAILED ||
        code == RESPONSE_OUTCOME_UNKNOWN)
        return child_status == 255U && output_length == 0U;
    return 0;
}

enum pm3000_acme_admin_result pm3000_acme_admin_call(
    const char *helper_path, unsigned int opcode,
    const char *revision,
    const unsigned char *body, size_t body_length,
    struct pm3000_acme_admin_response *response)
{
    int channel[2] = {-1, -1};
    pid_t child = -1;
    unsigned char request[FRAME_SIZE];
    unsigned char reply[FRAME_SIZE];
    uint32_t payload_length = 0U;
    unsigned int response_code = 255U;
    int receive_result = -1;
    int eof_result = -1;
    int child_status_value = 0;
    int reaped = -1;
    int request_sent = 0;
    long long deadline;
    enum pm3000_acme_admin_result result = PM3000_ACME_ADMIN_UNAVAILABLE;

    if (response != NULL) {
        response->child_status = 255U;
        response->output_length = 0U;
    }
    if (response == NULL || helper_path == NULL || helper_path[0] != '/' ||
        !valid_request(opcode, body, body_length, revision))
        return PM3000_ACME_ADMIN_BAD_REQUEST;
    if (socketpair(AF_UNIX, SOCK_STREAM, 0, channel) != 0) goto done;
    if (fcntl(channel[0], F_SETFD, FD_CLOEXEC) != 0 ||
        fcntl(channel[1], F_SETFD, FD_CLOEXEC) != 0)
        goto done;
    child = fork();
    if (child < 0) goto done;
    if (child == 0) {
        char *const arguments[] = {(char *)helper_path, NULL};
        char *const environment[] = {NULL};
        (void)close(channel[0]);
        if (dup2(channel[1], STDIN_FILENO) < 0 ||
            dup2(channel[1], STDOUT_FILENO) < 0)
            _exit(126);
        if (channel[1] != STDIN_FILENO && channel[1] != STDOUT_FILENO)
            (void)close(channel[1]);
        close_inherited_descriptors();
        execve(helper_path, arguments, environment);
        _exit(127);
    }
    (void)close(channel[1]);
    channel[1] = -1;
    {
        int flags = fcntl(channel[0], F_GETFL, 0);
        if (flags < 0 || fcntl(channel[0], F_SETFL, flags | O_NONBLOCK) != 0)
            goto done;
    }

    memcpy(request, protocol_magic, sizeof(protocol_magic));
    request[4] = (unsigned char)opcode;
    request[5] = 0U; request[6] = 0U; request[7] = 0U;
    encode_u32(request + 8U, (uint32_t)(body_length +
               (revision == NULL ? 0U : PM3000_ACME_ADMIN_ETAG_LENGTH)));
    deadline = monotonic_milliseconds();
    if (deadline < 0) goto done;
    deadline += PM3000_ACME_ADMIN_TIMEOUT_MS;
    if (send_all(channel[0], request, sizeof(request), deadline) != 0 ||
        (revision != NULL &&
         send_all(channel[0], (const unsigned char *)revision,
                  PM3000_ACME_ADMIN_ETAG_LENGTH, deadline) != 0) ||
        (body_length != 0U && send_all(channel[0], body, body_length, deadline) != 0))
        goto transport_failure;
    request_sent = 1;
    if (shutdown(channel[0], SHUT_WR) != 0) goto transport_failure;

    deadline = monotonic_milliseconds();
    if (deadline < 0) goto transport_failure;
    deadline += PM3000_ACME_ADMIN_TIMEOUT_MS;
    receive_result = receive_exact(channel[0], reply, sizeof(reply), deadline);
    if (receive_result != 0) goto transport_failure;
    if (memcmp(reply, protocol_magic, sizeof(protocol_magic)) != 0 ||
        reply[6] != 0U || reply[7] != 0U)
        goto protocol_failure;
    response_code = reply[4];
    response->child_status = reply[5];
    payload_length = decode_u32(reply + 8U);
    if (payload_length > PM3000_ACME_ADMIN_OUTPUT_LIMIT)
        goto protocol_failure;
    response->output_length = (size_t)payload_length;
    if (payload_length != 0U &&
        receive_exact(channel[0], response->output, payload_length, deadline) != 0)
        goto protocol_failure;
    eof_result = expect_eof(channel[0], deadline);
    if (eof_result != 0) goto protocol_failure;
    if ((response_code == RESPONSE_BUSY ||
         response_code == RESPONSE_STARTUP_FAILED ||
         response_code == RESPONSE_OUTCOME_UNKNOWN) &&
        opcode != PM3000_ACME_ADMIN_RENEW_ASYNC)
        goto protocol_failure;
    if (!response_is_consistent(response_code, response->child_status,
                                response->output_length))
        goto protocol_failure;
    if (response_code == RESPONSE_OK) result = PM3000_ACME_ADMIN_SUCCESS;
    else if (response_code == RESPONSE_BAD_REQUEST) result = PM3000_ACME_ADMIN_BAD_REQUEST;
    else if (response_code == RESPONSE_EXEC_FAILED) result = PM3000_ACME_ADMIN_UNAVAILABLE;
    else if (response_code == RESPONSE_CHILD_FAILED) result = PM3000_ACME_ADMIN_CHILD_FAILED;
    else if (response_code == RESPONSE_BUSY) result = PM3000_ACME_ADMIN_BUSY;
    else if (response_code == RESPONSE_STARTUP_FAILED) result = PM3000_ACME_ADMIN_STARTUP_FAILED;
    else if (response_code == RESPONSE_OUTCOME_UNKNOWN) result = PM3000_ACME_ADMIN_OUTCOME_UNKNOWN;
    else if (is_mutation(opcode)) result = PM3000_ACME_ADMIN_OUTCOME_UNKNOWN;
    else result = PM3000_ACME_ADMIN_PROTOCOL_ERROR;
    goto done;

protocol_failure:
    response->output_length = 0U;
    result = PM3000_ACME_ADMIN_PROTOCOL_ERROR;
    goto done;

transport_failure:
    response->output_length = 0U;
    result = request_sent && is_mutation(opcode)
                 ? PM3000_ACME_ADMIN_OUTCOME_UNKNOWN
                 : PM3000_ACME_ADMIN_UNAVAILABLE;

done:
    if (channel[0] >= 0) (void)close(channel[0]);
    if (channel[1] >= 0) (void)close(channel[1]);
    if (child > 0) {
        reaped = terminate_and_reap(child, &child_status_value);
        if (receive_result == 1 && reaped == 0 && WIFEXITED(child_status_value) &&
            WEXITSTATUS(child_status_value) == 127)
            result = PM3000_ACME_ADMIN_UNAVAILABLE;
        else if (reaped != 0 && result != PM3000_ACME_ADMIN_PROTOCOL_ERROR)
            result = request_sent && is_mutation(opcode)
                         ? PM3000_ACME_ADMIN_OUTCOME_UNKNOWN
                         : PM3000_ACME_ADMIN_UNAVAILABLE;
    }
    return result;
}
