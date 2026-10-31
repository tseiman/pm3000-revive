#define _POSIX_C_SOURCE 200809L

#include "session.h"
#include "controller_xml.h"
#include "projector.h"

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#define SESSION_LIFETIME 900
#define SESSION_FILE_LIMIT 1024U
#define CLEANUP_LIMIT 16U

static const char *const allowed_paths[PM3000_SESSION_PATH_COUNT] = {
    "units.topology",
    "units.overview",
    "units.powermanagement",
    "units.powermanagement.pdu_management",
    "units.powermanagement.powerprofile_login",
    "units.powermanagement.outlet_groups",
    "units.powermanagement.data_logging",
    "units.applianceSettings",
    "units.applianceSettings.security",
    "units.applianceSettings.security.SecurityProfileNav",
    "units.applianceSettings.security.SecurityDSView",
    "units.applianceSettings.date_and_time",
    "units.applianceSettings.date_and_time.date_time",
    "units.applianceSettings.date_and_time.time_zone",
    "units.applianceSettings.help",
    "units.applianceSettings.bootconfiguration",
    "units.applianceSettings.information",
    "units.applianceSettings.usage",
    "units.applianceSettings.usage.memory",
    "units.applianceSettings.usage.flashUsage",
    "units.network",
    "units.network.networkSettings",
    "units.network.devices",
    "units.network.ipv4_st_routes",
    "units.network.ipv6_st_routes",
    "units.network.hosts",
    "units.network.firewall",
    "units.network.firewall.filter4Table",
    "units.network.firewall.filter6Table",
    "units.network.SNMP",
    "units.authentication",
    "units.authentication.unit_authentication",
    "units.authentication.authenticationservers",
    "units.authentication.authenticationservers.radius",
    "units.authentication.authenticationservers.Tacacsplus",
    "units.authentication.authenticationservers.ldap_ad",
    "units.authentication.authenticationservers.kerberos",
    "units.authentication.authenticationservers.nis",
    "units.authentication.authenticationservers.dsviewsrv",
    "units.users",
    "units.users.local_accounts",
    "units.users.local_accounts.user_names",
    "units.users.local_accounts.password_rules",
    "units.users.authorization",
    "units.users.authorization.authorgroups",
    "units.event_notification",
    "units.event_notification.events",
    "units.event_notification.settings",
    "units.event_notification.global_settings_databuffering",
    "units.event_notification.sessions",
    "units.activeSessions",
    "units.monitoring",
    "units.monitoring.networkmon",
    "units.monitoring.networkmon.monitoringDevice",
    "units.monitoring.networkmon.monitoringIpv4RouteTable",
    "units.monitoring.networkmon.monitoringIpv6RouteTable",
    "units.monitoring.serialstatistics",
    "units.change_password"
};

static void set_error(char *error, unsigned int size, const char *message) {
    if (error != NULL && size > 0U) (void)snprintf(error, size, "%s", message);
}

static int valid_identifier(const char *value, size_t expected) {
    size_t index;
    if (value == NULL || strlen(value) != expected) return 0;
    for (index = 0U; index < expected; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '-' || c == '_')) return 0;
    }
    return 1;
}

static int safe_line(const char *value, size_t maximum) {
    const unsigned char *cursor = (const unsigned char *)value;
    size_t length = value == NULL ? 0U : strlen(value);
    if (length == 0U || length > maximum) return 0;
    while (*cursor != 0U) {
        if (*cursor < 0x20U || *cursor == 0x7fU) return 0;
        ++cursor;
    }
    return 1;
}

static int secure_random(unsigned char *output, size_t length) {
    int descriptor;
    struct stat metadata;
    size_t used = 0U;
    descriptor = open("/dev/urandom", O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISCHR(metadata.st_mode)) {
        if (descriptor >= 0) (void)close(descriptor);
        return -1;
    }
    while (used < length) {
        ssize_t amount = read(descriptor, output + used, length - used);
        if (amount <= 0) { (void)close(descriptor); return -1; }
        used += (size_t)amount;
    }
    return close(descriptor);
}

static void base64url(const unsigned char *input, size_t length, char *output) {
    static const char alphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    size_t in = 0U, out = 0U;
    while (in + 3U <= length) {
        uint32_t value = ((uint32_t)input[in] << 16) |
                         ((uint32_t)input[in + 1U] << 8) | input[in + 2U];
        output[out++] = alphabet[(value >> 18) & 63U];
        output[out++] = alphabet[(value >> 12) & 63U];
        output[out++] = alphabet[(value >> 6) & 63U];
        output[out++] = alphabet[value & 63U];
        in += 3U;
    }
    if (in < length) {
        uint32_t value = (uint32_t)input[in] << 16;
        output[out++] = alphabet[(value >> 18) & 63U];
        if (in + 1U < length) {
            value |= (uint32_t)input[in + 1U] << 8;
            output[out++] = alphabet[(value >> 12) & 63U];
            output[out++] = alphabet[(value >> 6) & 63U];
        } else output[out++] = alphabet[(value >> 12) & 63U];
    }
    output[out] = '\0';
}

static int open_directory(const char *path, int create, int *descriptor) {
    struct stat metadata;
    if (path == NULL || path[0] != '/') return -1;
    if (create && mkdir(path, 0700) != 0 && errno != EEXIST) return -1;
    *descriptor = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (*descriptor < 0 || fstat(*descriptor, &metadata) != 0 ||
        !S_ISDIR(metadata.st_mode) || metadata.st_uid != getuid() ||
        (metadata.st_mode & 0777U) != 0700U) {
        if (*descriptor >= 0) (void)close(*descriptor);
        *descriptor = -1;
        return -1;
    }
    return 0;
}

static int parse_navigation(const unsigned char *xml, size_t length,
                            const unsigned char *topology, size_t topology_length,
                            uint64_t *path_mask, int *can_manage,
                            int *can_control, int *can_help_language,
                            int *can_data_buffering,
                            int *can_appliance_logging,
                            int *can_time_zone,
                            int *can_manage_acme) {
    char error[160] = {0};
    if (pm3000_xml_navigation(xml, length, allowed_paths,
                              PM3000_SESSION_PATH_COUNT, path_mask,
                              can_manage, can_help_language,
                              can_data_buffering,
                              can_appliance_logging,
                              can_time_zone,
                              can_manage_acme) != 0) return -1;
    *can_control = 0;
    if (topology == NULL || topology_length == 0U) return 0;
    return pm3000_project_bytes(topology, (unsigned long)topology_length,
                                NULL, error, sizeof(error)) == 0 &&
           pm3000_xml_topology_controls(topology, topology_length,
                                        can_control) == 0 ? 0 : -1;
}

static int serialize(const pm3000_session *session, time_t expires,
                     char output[SESSION_FILE_LIMIT + 1U], size_t *length) {
    unsigned int flags = (session->can_manage_tokens ? 1U : 0U) |
                         (session->can_control_power ? 2U : 0U) |
                         (session->can_help_language ? 4U : 0U) |
                         (session->can_data_buffering ? 8U : 0U) |
                         (session->can_appliance_logging ? 16U : 0U) |
                         (session->can_time_zone ? 32U : 0U) |
                         (session->can_manage_acme ? 64U : 0U);
    int amount = snprintf(output, SESSION_FILE_LIMIT + 1U,
                          "PM3000_SESSION_V1\n%lld\n%s\n%s\n%s\n%llu\n%u\n",
                          (long long)expires, session->sid, session->csrf,
                          session->username, (unsigned long long)session->path_mask, flags);
    if (amount <= 0 || (size_t)amount > SESSION_FILE_LIMIT) return -1;
    *length = (size_t)amount;
    return 0;
}

static int write_all(int descriptor, const char *data, size_t length) {
    size_t used = 0U;
    while (used < length) {
        ssize_t amount = write(descriptor, data + used, length - used);
        if (amount <= 0) return -1;
        used += (size_t)amount;
    }
    return 0;
}

static int parse_unsigned64(const char *value, uint64_t *output) {
    char *end = NULL;
    unsigned long long parsed;
    if (value == NULL || value[0] == '\0' || value[0] == '-' || value[0] == '+') return -1;
    errno = 0;
    parsed = strtoull(value, &end, 10);
    if (errno != 0 || end == value || *end != '\0') return -1;
    *output = (uint64_t)parsed;
    return 0;
}

static int parse_file(char *data, size_t length, pm3000_session *session,
                      time_t *expires) {
    char *lines[8];
    size_t count = 0U, index;
    char *cursor = data;
    char *end = NULL;
    long long parsed_expiry;
    uint64_t flags;
    if (length == 0U || data[length - 1U] != '\n' || memchr(data, 0, length) != NULL) return -1;
    data[length] = '\0';
    lines[count++] = cursor;
    for (index = 0U; index < length; ++index) {
        if (data[index] == '\n') {
            data[index] = '\0';
            if (index + 1U < length) {
                if (count >= sizeof(lines) / sizeof(lines[0])) return -1;
                lines[count++] = data + index + 1U;
            }
        }
    }
    if (count != 7U || strcmp(lines[0], "PM3000_SESSION_V1") != 0) return -1;
    errno = 0;
    parsed_expiry = strtoll(lines[1], &end, 10);
    if (errno != 0 || end == lines[1] || *end != '\0' || parsed_expiry <= 0) return -1;
    if (!safe_line(lines[2], 128U) || !valid_identifier(lines[3], PM3000_CSRF_LENGTH) ||
        !safe_line(lines[4], 128U) || parse_unsigned64(lines[5], &session->path_mask) != 0 ||
        session->path_mask >= (UINT64_C(1) << PM3000_SESSION_PATH_COUNT) ||
        parse_unsigned64(lines[6], &flags) != 0 || flags > 127U) return -1;
    strcpy(session->sid, lines[2]);
    strcpy(session->csrf, lines[3]);
    strcpy(session->username, lines[4]);
    session->can_manage_tokens = (flags & 1U) != 0U;
    session->can_control_power = (flags & 2U) != 0U;
    session->can_help_language = (flags & 4U) != 0U;
    session->can_data_buffering = (flags & 8U) != 0U;
    session->can_appliance_logging = (flags & 16U) != 0U;
    session->can_time_zone = (flags & 32U) != 0U;
    session->can_manage_acme = (flags & 64U) != 0U;
    *expires = (time_t)parsed_expiry;
    if ((long long)*expires != parsed_expiry) return -1;
    return 0;
}

static int read_session_fd(int descriptor, pm3000_session *session,
                           time_t *expires) {
    struct stat metadata;
    char buffer[SESSION_FILE_LIMIT + 1U];
    size_t used = 0U;
    if (fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_nlink != 1U || metadata.st_uid != getuid() ||
        (metadata.st_mode & 0777U) != 0600U || metadata.st_size <= 0 ||
        metadata.st_size > (off_t)SESSION_FILE_LIMIT) return -1;
    if (lseek(descriptor, 0, SEEK_SET) < 0) return -1;
    while (used < (size_t)metadata.st_size) {
        ssize_t amount = read(descriptor, buffer + used, (size_t)metadata.st_size - used);
        if (amount <= 0) return -1;
        used += (size_t)amount;
    }
    return parse_file(buffer, used, session, expires);
}

static int current_entry_matches(int directory_fd, const char *name,
                                 int descriptor) {
    struct stat opened, current;
    return fstat(descriptor, &opened) == 0 &&
           fstatat(directory_fd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
           S_ISREG(current.st_mode) && opened.st_dev == current.st_dev &&
           opened.st_ino == current.st_ino && opened.st_nlink == 1U &&
           current.st_nlink == 1U;
}

#ifdef PM3000_TESTING
static int inject_path_replacement(int directory_fd, const char *identifier) {
    int replacement;
    (void)unlinkat(directory_fd, ".session-path-fault", 0);
    if (renameat(directory_fd, identifier, directory_fd,
                 ".session-path-fault") != 0) return -1;
    replacement = openat(directory_fd, identifier,
                         O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                         0600);
    if (replacement < 0 || write_all(replacement, "replaced\n", 9U) != 0) {
        if (replacement >= 0) (void)close(replacement);
        return -1;
    }
    if (close(replacement) != 0) return -1;
    (void)unlinkat(directory_fd, ".session-path-fault", 0);
    return 0;
}
#endif

static void cleanup_expired(int directory_fd, time_t now) {
    DIR *stream;
    struct dirent *entry;
    unsigned int inspected = 0U;
    int duplicate = dup(directory_fd);
    if (duplicate < 0) return;
    stream = fdopendir(duplicate);
    if (stream == NULL) { (void)close(duplicate); return; }
    while (inspected < CLEANUP_LIMIT && (entry = readdir(stream)) != NULL) {
        int descriptor;
        pm3000_session ignored;
        time_t expires;
        if (!valid_identifier(entry->d_name, PM3000_SESSION_ID_LENGTH)) continue;
        ++inspected;
        descriptor = openat(directory_fd, entry->d_name,
                            O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
        if (descriptor < 0) continue;
        if (flock(descriptor, LOCK_EX | LOCK_NB) == 0) {
            if (read_session_fd(descriptor, &ignored, &expires) == 0 && expires <= now &&
                current_entry_matches(directory_fd, entry->d_name, descriptor))
                (void)unlinkat(directory_fd, entry->d_name, 0);
            (void)flock(descriptor, LOCK_UN);
        }
        (void)close(descriptor);
    }
    (void)closedir(stream);
}

int pm3000_session_create(const char *directory, const char *username,
                          const char *sid, const unsigned char *navigation,
                          size_t navigation_length, const unsigned char *topology,
                          size_t topology_length, pm3000_session *session,
                          char *error, unsigned int error_size) {
    int directory_fd = -1, descriptor = -1;
    unsigned char random[64];
    char serialized[SESSION_FILE_LIMIT + 1U];
    size_t length;
    time_t now;
    unsigned int attempt;
    memset(session, 0, sizeof(*session));
    if (!safe_line(username, 128U) || !safe_line(sid, 128U) ||
        parse_navigation(navigation, navigation_length, topology, topology_length,
                         &session->path_mask,
                         &session->can_manage_tokens, &session->can_control_power,
                          &session->can_help_language,
                          &session->can_data_buffering,
                          &session->can_appliance_logging,
                          &session->can_time_zone,
                          &session->can_manage_acme) != 0) {
        set_error(error, error_size, "session metadata rejected");
        return -1;
    }
    strcpy(session->username, username);
    strcpy(session->sid, sid);
    if (secure_random(random, sizeof(random)) != 0) goto failure;
    base64url(random, 32U, session->id);
    base64url(random + 32U, 32U, session->csrf);
    now = time(NULL);
    if (now == (time_t)-1 || now > (time_t)(LLONG_MAX - SESSION_LIFETIME) ||
        serialize(session, now + SESSION_LIFETIME, serialized, &length) != 0 ||
        open_directory(directory, 1, &directory_fd) != 0 ||
        flock(directory_fd, LOCK_EX) != 0) goto failure;
    cleanup_expired(directory_fd, now);
    for (attempt = 0U; attempt < 8U; ++attempt) {
        descriptor = openat(directory_fd, session->id,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (descriptor >= 0) break;
        if (errno != EEXIST || secure_random(random, 32U) != 0) goto failure;
        base64url(random, 32U, session->id);
    }
    if (descriptor < 0 || write_all(descriptor, serialized, length) != 0 ||
        fsync(descriptor) != 0 || close(descriptor) != 0) {
        if (descriptor >= 0) (void)close(descriptor);
        descriptor = -1;
        (void)unlinkat(directory_fd, session->id, 0);
        goto failure;
    }
    descriptor = -1;
    if (fsync(directory_fd) != 0) {
        (void)unlinkat(directory_fd, session->id, 0);
        goto failure;
    }
    (void)close(directory_fd);
    memset(random, 0, sizeof(random));
    return 0;
failure:
    if (descriptor >= 0) (void)close(descriptor);
    if (directory_fd >= 0) (void)close(directory_fd);
    memset(random, 0, sizeof(random));
    memset(session, 0, sizeof(*session));
    set_error(error, error_size, "session store unavailable");
    return -1;
}

int pm3000_session_load(const char *directory, const char *identifier,
                        int refresh, pm3000_session *session,
                        char *error, unsigned int error_size) {
    int directory_fd = -1, descriptor = -1;
    time_t expires, now;
    int result = -1;
    memset(session, 0, sizeof(*session));
    if (!valid_identifier(identifier, PM3000_SESSION_ID_LENGTH) ||
        open_directory(directory, 0, &directory_fd) != 0 ||
        flock(directory_fd, LOCK_EX) != 0) goto done;
    descriptor = openat(directory_fd, identifier,
                        (refresh ? O_RDWR : O_RDONLY) | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || flock(descriptor, refresh ? LOCK_EX : LOCK_SH) != 0 ||
        !current_entry_matches(directory_fd, identifier, descriptor) ||
        read_session_fd(descriptor, session, &expires) != 0) goto done;
    strcpy(session->id, identifier);
    now = time(NULL);
    if (now == (time_t)-1 || expires <= now) {
        if (current_entry_matches(directory_fd, identifier, descriptor))
            (void)unlinkat(directory_fd, identifier, 0);
        goto done;
    }
    if (refresh) {
        char serialized[SESSION_FILE_LIMIT + 1U];
        size_t length;
#ifdef PM3000_TESTING
        if (getenv("PM3000_SESSION_FAULT") != NULL &&
            strcmp(getenv("PM3000_SESSION_FAULT"), "replace_before_refresh") == 0 &&
            inject_path_replacement(directory_fd, identifier) != 0) goto done;
#endif
        if (now > (time_t)(LLONG_MAX - SESSION_LIFETIME) ||
            serialize(session, now + SESSION_LIFETIME, serialized, &length) != 0 ||
            !current_entry_matches(directory_fd, identifier, descriptor) ||
            ftruncate(descriptor, 0) != 0 || lseek(descriptor, 0, SEEK_SET) < 0 ||
            write_all(descriptor, serialized, length) != 0 || fsync(descriptor) != 0)
            goto done;
    }
    result = 0;
done:
    if (descriptor >= 0) { (void)flock(descriptor, LOCK_UN); (void)close(descriptor); }
    if (directory_fd >= 0) (void)close(directory_fd);
    if (result != 0) {
        memset(session, 0, sizeof(*session));
        set_error(error, error_size, "session rejected");
    }
    return result;
}

int pm3000_session_delete(const char *directory, const char *identifier,
                          char *error, unsigned int error_size) {
    int directory_fd = -1, descriptor = -1;
    int result = -1;
    if (!valid_identifier(identifier, PM3000_SESSION_ID_LENGTH) ||
        open_directory(directory, 0, &directory_fd) != 0 ||
        flock(directory_fd, LOCK_EX) != 0) goto done;
    descriptor = openat(directory_fd, identifier,
                        O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || flock(descriptor, LOCK_EX) != 0 ||
        !current_entry_matches(directory_fd, identifier, descriptor)) goto done;
#ifdef PM3000_TESTING
    if (getenv("PM3000_SESSION_FAULT") != NULL &&
        strcmp(getenv("PM3000_SESSION_FAULT"), "replace_before_delete") == 0) {
        if (inject_path_replacement(directory_fd, identifier) != 0) goto done;
    }
#endif
    if (!current_entry_matches(directory_fd, identifier, descriptor)) goto done;
    if (unlinkat(directory_fd, identifier, 0) == 0 && fsync(directory_fd) == 0) result = 0;
done:
    if (descriptor >= 0) { (void)flock(descriptor, LOCK_UN); (void)close(descriptor); }
    if (directory_fd >= 0) (void)close(directory_fd);
    if (result != 0) set_error(error, error_size, "session teardown failed");
    return result;
}

int pm3000_session_csrf_matches(const pm3000_session *session, const char *value) {
    unsigned char difference = 0U;
    size_t index;
    if (value == NULL || strlen(value) != PM3000_CSRF_LENGTH) return 0;
    for (index = 0U; index < PM3000_CSRF_LENGTH; ++index)
        difference |= (unsigned char)session->csrf[index] ^ (unsigned char)value[index];
    return difference == 0U;
}

int pm3000_session_has_path(const pm3000_session *session, const char *path) {
    unsigned int index;
    for (index = 0U; index < PM3000_SESSION_PATH_COUNT; ++index)
        if (strcmp(allowed_paths[index], path) == 0)
            return (session->path_mask & (UINT64_C(1) << index)) != 0U;
    return 0;
}

static void json_string(FILE *output, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    fputc('"', output);
    while (*cursor != 0U) {
        if (*cursor == '"' || *cursor == '\\') { fputc('\\', output); fputc(*cursor, output); }
        else if (*cursor < 0x20U) fprintf(output, "\\u%04x", (unsigned int)*cursor);
        else fputc(*cursor, output);
        ++cursor;
    }
    fputc('"', output);
}

int pm3000_session_write_json(FILE *output, const pm3000_session *session) {
    unsigned int index;
    int first = 1;
    fputs("{\"identity\":{\"username\":", output);
    json_string(output, session->username);
    fputs("},\"csrfToken\":", output);
    json_string(output, session->csrf);
    fputs(",\"navigation\":{\"paths\":[", output);
    for (index = 0U; index < PM3000_SESSION_PATH_COUNT; ++index) {
        if ((session->path_mask & (UINT64_C(1) << index)) == 0U) continue;
        if (!first) fputc(',', output);
        first = 0;
        json_string(output, allowed_paths[index]);
    }
    fprintf(output, "],\"canManageTokens\":%s,\"canControlPower\":%s,\"canManageAcme\":%s}}\n",
            session->can_manage_tokens ? "true" : "false",
            session->can_control_power ? "true" : "false",
            session->can_manage_acme ? "true" : "false");
    return ferror(output) ? -1 : 0;
}
