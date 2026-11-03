/* Fixed-purpose ACME administration broker.
 * Installed setuid-root and executable only by the Apache daemon group.
 */
#define _POSIX_C_SOURCE 200809L

#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <pwd.h>
#include <signal.h>
#include <stdio.h>
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
#define PM3000_ACME_EXECUTABLE "/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme-maintenance"
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
#define OP_SCHEDULE_SHOW 10U
#define OP_SCHEDULE_REPLACE 11U
#define OP_SCHEDULE_CREATE 12U

#ifndef PM3000_SCHEDULE_PATH
#define PM3000_SCHEDULE_PATH "/mnt/hdUser/pm3000-revive/acme/schedule-v1"
#endif
#ifndef PM3000_CRONTAB_PATH
#define PM3000_CRONTAB_PATH "/etc/cron/crontabs/root"
#endif
#define SCHEDULE_BEGIN "# BEGIN PM3000 ACME SCHEDULE\n"
#define SCHEDULE_END "# END PM3000 ACME SCHEDULE\n"
#define SCHEDULE_COMMAND "/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-acme-maintenance scheduled"
#ifndef PM3000_CRON_INIT
#define PM3000_CRON_INIT "/etc/init.d/busybox-cron"
#endif
#define CRON_INIT PM3000_CRON_INIT
#define CRONTAB_LIMIT 65536U

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

/* Shell interpreters may discard an inherited effective root identity when
 * real and effective IDs differ. Every exec target and argv below is fixed by
 * this broker, so normalize only after the PMA1 request has been validated. */
static int normalize_root_identity(void)
{
    if (setgid(0U) != 0) return -1;
    if (setuid(0U) != 0) return -1;
    return 0;
}

static int redirect_standard_to_null(void)
{
    int descriptor = open("/dev/null", O_RDWR);
    if (descriptor < 0) return -1;
    if (dup2(descriptor, STDIN_FILENO) < 0 ||
        dup2(descriptor, STDOUT_FILENO) < 0 ||
        dup2(descriptor, STDERR_FILENO) < 0) {
        if (descriptor > STDERR_FILENO) (void)close(descriptor);
        return -1;
    }
    if (descriptor > STDERR_FILENO && close(descriptor) != 0) return -1;
    return 0;
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
        arguments[1] = (char *)"force";
        arguments[2] = (char *)"--broker-startup-notify";
        arguments[3] = NULL;
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
    if (opcode == OP_SCHEDULE_SHOW && length == 0U) return 1;
    if (opcode == OP_SCHEDULE_REPLACE && length == ETAG_LENGTH + 3U) return 1;
    if (opcode == OP_SCHEDULE_CREATE && length == 3U) return 1;
    return 0;
}

static int safe_regular(int fd, mode_t mode)
{
    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_nlink != 1U)
        return 0;
#ifndef PM3000_TESTING
    if (st.st_uid != 0U || st.st_gid != 0U) return 0;
#endif
    return (st.st_mode & 0777U) == mode;
}

static int lock_schedule(void)
{
    char path[512]; struct flock lock; int fd; int amount;
    amount = snprintf(path, sizeof(path), "%s.lock", PM3000_SCHEDULE_PATH);
    if (amount < 0 || (size_t)amount >= sizeof(path)) return -1;
    fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600U);
    if (fd < 0) return -1;
#ifndef PM3000_TESTING
    if (fchown(fd, 0U, 0U) != 0) { (void)close(fd); return -1; }
#endif
    if (fchmod(fd, 0600U) != 0 || !safe_regular(fd, 0600U)) {
        (void)close(fd); return -1;
    }
    memset(&lock, 0, sizeof(lock)); lock.l_type = F_WRLCK; lock.l_whence = SEEK_SET;
    while (fcntl(fd, F_SETLKW, &lock) != 0) {
        if (errno != EINTR) { (void)close(fd); return -1; }
    }
    return fd;
}

static void schedule_etag(const unsigned char value[3], char output[67])
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    output[0] = '"';
    for (i = 0U; i < 32U; ++i) {
        unsigned char byte = i < 3U ? value[i] : (unsigned char)(0xa5U ^ i);
        output[1U + i * 2U] = hex[byte >> 4];
        output[2U + i * 2U] = hex[byte & 15U];
    }
    output[65] = '"'; output[66] = '\0';
}

/* 0=managed, 1=absent, -1=unsafe/malformed. */
static int read_schedule(unsigned char value[3])
{
    int fd = open(PM3000_SCHEDULE_PATH, O_RDONLY | O_NOFOLLOW);
    unsigned char data[4];
    ssize_t amount;
    if (fd < 0) return errno == ENOENT ? 1 : -1;
    if (!safe_regular(fd, 0600U)) { (void)close(fd); return -1; }
    amount = read(fd, data, sizeof(data));
    if (amount != 3 || read(fd, data + 3, 1U) != 0) { (void)close(fd); return -1; }
    (void)close(fd);
    if (data[0] > 1U || data[1] > 23U || data[2] > 59U) return -1;
    memcpy(value, data, 3U);
    return 0;
}

static int read_crontab(unsigned char **data, size_t *length)
{
    int fd = open(PM3000_CRONTAB_PATH, O_RDONLY | O_NOFOLLOW);
    unsigned char *buffer;
    size_t used = 0U;
    if (fd < 0) {
        if (errno == ENOENT) { *data = NULL; *length = 0U; return 0; }
        return -1;
    }
    if (!safe_regular(fd, 0600U)) { (void)close(fd); return -1; }
    buffer = malloc(CRONTAB_LIMIT + 1U);
    if (buffer == NULL) { (void)close(fd); return -1; }
    while (used <= CRONTAB_LIMIT) {
        ssize_t amount = read(fd, buffer + used, CRONTAB_LIMIT + 1U - used);
        if (amount < 0 && errno == EINTR) continue;
        if (amount < 0) { free(buffer); (void)close(fd); return -1; }
        if (amount == 0) break;
        used += (size_t)amount;
    }
    (void)close(fd);
    if (used > CRONTAB_LIMIT) { free(buffer); return -1; }
    *data = buffer; *length = used; return 0;
}

static int find_managed_block(const unsigned char *data, size_t length,
                              size_t *start, size_t *end)
{
    const char *begin = SCHEDULE_BEGIN, *finish = SCHEDULE_END;
    size_t blen = strlen(begin), elen = strlen(finish), i;
    unsigned int begins = 0U, ends = 0U;
    size_t bpos = 0U, epos = 0U;
    for (i = 0U; i < length; ++i) {
        if ((i == 0U || data[i - 1U] == '\n') && i + blen <= length &&
            memcmp(data + i, begin, blen) == 0) { ++begins; bpos = i; }
        if ((i == 0U || data[i - 1U] == '\n') && i + elen <= length &&
            memcmp(data + i, finish, elen) == 0) { ++ends; epos = i + elen; }
    }
    if (begins == 0U && ends == 0U) return 0;
    if (begins != 1U || ends != 1U || bpos >= epos) return -1;
    *start = bpos; *end = epos; return 1;
}

static int exact_existing_block(const unsigned char *data, size_t start, size_t end,
                                const unsigned char current[3])
{
    char expected[256]; int amount;
    if (!current[0]) return 0;
    amount = snprintf(expected, sizeof(expected), SCHEDULE_BEGIN "%u %u * * * "
                      SCHEDULE_COMMAND "\n" SCHEDULE_END,
                      (unsigned int)current[2], (unsigned int)current[1]);
    return amount > 0 && (size_t)amount == end - start &&
           memcmp(data + start, expected, (size_t)amount) == 0;
}

static int fsync_parent(const char *path)
{
    char parent[512]; char *slash; int descriptor; int result;
    if (strlen(path) >= sizeof(parent)) return -1;
    strcpy(parent, path); slash = strrchr(parent, '/');
    if (slash == NULL || slash == parent) return -1;
    *slash = '\0';
    descriptor = open(parent, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (descriptor < 0) return -1;
    result = fsync(descriptor);
    if (close(descriptor) != 0) result = -1;
    return result;
}

static int publish_file(const char *path, const unsigned char *data, size_t length)
{
    char temporary[512]; int fd; size_t used = 0U;
    int amount = snprintf(temporary, sizeof(temporary), "%s.tmp.%ld", path, (long)getpid());
    if (amount < 0 || (size_t)amount >= sizeof(temporary)) return -1;
    fd = open(temporary, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, 0600U);
    if (fd < 0) return -1;
#ifndef PM3000_TESTING
    if (fchown(fd, 0U, 0U) != 0) { (void)close(fd); (void)unlink(temporary); return -1; }
#endif
    if (fchmod(fd, 0600U) != 0) { (void)close(fd); (void)unlink(temporary); return -1; }
    while (used < length) {
        ssize_t n = write(fd, data + used, length - used);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { (void)close(fd); (void)unlink(temporary); return -1; }
        used += (size_t)n;
    }
    if (fsync(fd) != 0 || close(fd) != 0 || rename(temporary, path) != 0) {
        (void)unlink(temporary); return -1;
    }
    /* rename committed the visible bytes; a later parent fsync failure is
     * durability-uncertain, not a safe precommit failure. */
    return fsync_parent(path) == 0 ? 0 : 1;
}

static int schedule_show(unsigned char *output, size_t *output_length)
{
    unsigned char value[3] = {0U, 3U, 17U};
    unsigned char *cron = NULL; size_t cron_length = 0U, start = 0U, end = 0U;
    char etag[67]; int managed = read_schedule(value), block, amount;
    if (managed < 0 || read_crontab(&cron, &cron_length) != 0) return RESPONSE_CHILD_FAILED;
    block = find_managed_block(cron, cron_length, &start, &end);
    if (block < 0 || (managed == 1 && block != 0) ||
        (managed == 0 && ((value[0] && (block != 1 || !exact_existing_block(cron, start, end, value))) ||
                          (!value[0] && block != 0)))) {
        free(cron); return RESPONSE_CHILD_FAILED;
    }
    free(cron);
    if (managed == 1) {
        amount = snprintf((char *)output, OUTPUT_LIMIT,
                          "{\"managed\":false,\"enabled\":false,\"hour\":3,\"minute\":17}\n");
    } else {
        schedule_etag(value, etag);
        amount = snprintf((char *)output, OUTPUT_LIMIT,
                          "{\"managed\":true,\"enabled\":%s,\"hour\":%u,\"minute\":%u,\"revision\":\"\\\"%.64s\\\"\"}\n",
                          value[0] ? "true" : "false", (unsigned int)value[1],
                          (unsigned int)value[2], etag + 1);
    }
    if (amount < 0 || (size_t)amount >= OUTPUT_LIMIT) return RESPONSE_OUTPUT_TOO_LARGE;
    *output_length = (size_t)amount; return RESPONSE_OK;
}

static int remove_published(const char *path)
{
    if (unlink(path) != 0 && errno != ENOENT) return -1;
    return fsync_parent(path);
}

static int reload_cron(void)
{
    pid_t child, waited; int status; char *const arguments[] = {(char *)CRON_INIT, (char *)"reload", NULL};
    char *const environment[] = {NULL};
    child = fork();
    if (child < 0) return -1;
    if (child == 0) {
        close_inherited_descriptors();
        if (redirect_standard_to_null() != 0) _exit(126);
        if (normalize_root_identity() != 0) _exit(126);
        execve(CRON_INIT, arguments, environment);
        _exit(127);
    }
    do { waited = waitpid(child, &status, 0); } while (waited < 0 && errno == EINTR);
    return waited == child && WIFEXITED(status) && WEXITSTATUS(status) == 0 ? 0 : -1;
}

static int schedule_replace(const unsigned char desired[3], const char *revision,
                            int creating)
{
    unsigned char current[3], *cron = NULL, *next = NULL;
    size_t cron_length = 0U, start = 0U, end = 0U, prefix, suffix;
    size_t block_length = 0U, boundary_length = 0U;
    char expected[67], block[256]; int state = read_schedule(current), found, amount;
    if (desired[0] > 1U || desired[1] > 23U || desired[2] > 59U) return RESPONSE_BAD_REQUEST;
    if ((creating && state != 1) || (!creating && state != 0)) return RESPONSE_CHILD_FAILED;
    if (!creating) { schedule_etag(current, expected); if (strcmp(expected, revision) != 0) return RESPONSE_CHILD_FAILED; }
    if (read_crontab(&cron, &cron_length) != 0) return RESPONSE_CHILD_FAILED;
    found = find_managed_block(cron, cron_length, &start, &end);
    if (found < 0 || (state == 1 && found != 0) ||
        (state == 0 && ((current[0] && (found != 1 || !exact_existing_block(cron, start, end, current))) ||
                        (!current[0] && found != 0)))) { free(cron); return RESPONSE_CHILD_FAILED; }
    if (found == 0) start = end = cron_length;
    if (desired[0]) {
        amount = snprintf(block, sizeof(block), SCHEDULE_BEGIN "%u %u * * * "
                          SCHEDULE_COMMAND "\n" SCHEDULE_END,
                          (unsigned int)desired[2], (unsigned int)desired[1]);
        if (amount < 0 || (size_t)amount >= sizeof(block)) { free(cron); return RESPONSE_CHILD_FAILED; }
        block_length = (size_t)amount;
    }
    prefix = start; suffix = cron_length - end;
    if (found == 0 && block_length != 0U && prefix != 0U && cron[prefix - 1U] != '\n')
        boundary_length = 1U;
    next = malloc(prefix + boundary_length + block_length + suffix + 1U);
    if (next == NULL) { free(cron); return RESPONSE_CHILD_FAILED; }
    if (prefix) memcpy(next, cron, prefix);
    if (boundary_length) next[prefix] = '\n';
    if (block_length) memcpy(next + prefix + boundary_length, block, block_length);
    if (suffix) memcpy(next + prefix + boundary_length + block_length, cron + end, suffix);
    {
        int published = publish_file(PM3000_CRONTAB_PATH, next,
                                     prefix + boundary_length + block_length + suffix);
        if (published != 0) {
            free(next); free(cron);
            return published > 0 ? RESPONSE_OUTCOME_UNKNOWN : RESPONSE_CHILD_FAILED;
        }
    }
    free(next);
    {
        int published = publish_file(PM3000_SCHEDULE_PATH, desired, 3U);
        if (published != 0) {
            int restored;
            if (published > 0) { free(cron); return RESPONSE_OUTCOME_UNKNOWN; }
            restored = cron == NULL
                ? remove_published(PM3000_CRONTAB_PATH)
                : publish_file(PM3000_CRONTAB_PATH, cron, cron_length);
            free(cron);
            return restored == 0 ? RESPONSE_CHILD_FAILED : RESPONSE_OUTCOME_UNKNOWN;
        }
    }
    free(cron);
    return reload_cron() == 0 ? RESPONSE_OK : RESPONSE_OUTCOME_UNKNOWN;
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
        if (normalize_root_identity() != 0) _exit(126);
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
    if (opcode != OP_CONFIG_REPLACE && opcode != OP_CA_INSTALL &&
        opcode != OP_SCHEDULE_REPLACE) return 1;
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
        if (normalize_root_identity() != 0) _exit(126);
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
    int schedule_lock = -1;
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
    if (opcode == OP_CONFIG_REPLACE || opcode == OP_CA_INSTALL ||
        opcode == OP_SCHEDULE_REPLACE) {
        arguments[5] = etag;
        input_length -= ETAG_LENGTH;
        memmove(input, input + ETAG_LENGTH, input_length);
    }
    if (opcode == OP_SCHEDULE_SHOW || opcode == OP_SCHEDULE_REPLACE ||
        opcode == OP_SCHEDULE_CREATE) {
        schedule_lock = lock_schedule();
        if (schedule_lock < 0) {
            response = RESPONSE_CHILD_FAILED;
            child_status = 5U;
        } else if (opcode == OP_SCHEDULE_SHOW) {
            response = schedule_show(output, &output_length);
            child_status = response == RESPONSE_OK ? 0U : 5U;
        } else {
            response = schedule_replace(input,
                                        opcode == OP_SCHEDULE_REPLACE ? etag : NULL,
                                        opcode == OP_SCHEDULE_CREATE);
            child_status = response == RESPONSE_OK ? 0U :
                           response == RESPONSE_OUTCOME_UNKNOWN ? 255U : 5U;
        }
        if (schedule_lock >= 0) (void)close(schedule_lock);
    } else if (opcode == OP_RENEW_ASYNC) {
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
