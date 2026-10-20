#define _POSIX_C_SOURCE 200809L

#include "avtrans.h"

#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_RESPONSE (1024U * 1024U)
#define MAX_CREDENTIALS 512U
#define MAX_REQUEST 2048U

static void set_error(char *error, unsigned int size, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, size, format, arguments);
    va_end(arguments);
}

static int read_credentials(const char *path, char username[129], char password[257],
                            char *error, unsigned int error_size) {
    int descriptor;
    struct stat metadata;
    unsigned char content[MAX_CREDENTIALS + 1U];
    ssize_t amount;
    char *first, *second;
    descriptor = open(path, O_RDONLY | O_NONBLOCK | O_NOFOLLOW | O_CLOEXEC);
    if (descriptor < 0 || fstat(descriptor, &metadata) != 0 || !S_ISREG(metadata.st_mode) ||
        metadata.st_nlink != 1U || metadata.st_uid != getuid() ||
        (metadata.st_mode & 0777U) != 0600U || metadata.st_size <= 0 || metadata.st_size > MAX_CREDENTIALS) {
        if (descriptor >= 0) close(descriptor);
        set_error(error, error_size, "service credentials rejected");
        return -1;
    }
    amount = read(descriptor, content, sizeof(content) - 1U);
    if (close(descriptor) != 0 || amount != metadata.st_size) {
        set_error(error, error_size, "service credentials read failed");
        return -1;
    }
    content[amount] = '\0';
    first = strchr((char *)content, '\n');
    if (first == NULL) { set_error(error, error_size, "service credentials rejected"); return -1; }
    *first++ = '\0';
    second = strchr(first, '\n');
    if (second == NULL || second[1] != '\0') { set_error(error, error_size, "service credentials rejected"); return -1; }
    *second = '\0';
    if (content[0] == '\0' || first[0] == '\0' || strlen((char *)content) > 128U || strlen(first) > 256U ||
        strpbrk((char *)content, "\r\t") != NULL || strpbrk(first, "\r\t") != NULL) {
        set_error(error, error_size, "service credentials rejected"); return -1;
    }
    strcpy(username, (char *)content);
    strcpy(password, first);
    memset(content, 0, sizeof(content));
    return 0;
}

static int xml_escape(const char *input, char *output, size_t capacity) {
    size_t used = 0;
    while (*input != '\0') {
        const char *replacement = NULL;
        size_t amount;
        unsigned char value = (unsigned char)*input++;
        if (value < 0x20U || value == 0x7fU) return -1;
        if (value == '&') replacement = "&amp;";
        else if (value == '<') replacement = "&lt;";
        else if (value == '>') replacement = "&gt;";
        else if (value == '"') replacement = "&quot;";
        else if (value == '\'') replacement = "&apos;";
        if (replacement != NULL) {
            amount = strlen(replacement);
            if (used + amount >= capacity) return -1;
            memcpy(output + used, replacement, amount); used += amount;
        } else {
            if (used + 1U >= capacity) return -1;
            output[used++] = (char)value;
        }
    }
    output[used] = '\0';
    return 0;
}

static int exchange(const char *socket_path, const char *request,
                    unsigned char **response, size_t *response_length,
                    char *error, unsigned int error_size) {
    int descriptor = -1;
    struct sockaddr_un address;
    struct timeval timeout = {3, 0};
    unsigned char header[59] = {0};
    unsigned char *buffer = NULL;
    size_t used = 0;
    int found_nul = 0;
    ssize_t amount;
    size_t request_length = strlen(request);
    if (strlen(socket_path) >= sizeof(address.sun_path) || request_length >= MAX_REQUEST) goto failure;
    descriptor = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (descriptor < 0) goto failure;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    strcpy(address.sun_path, socket_path);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) goto failure;
    header[2] = 1U;
    memcpy(header + 3U, "127.0.0.1", 9U);
    memcpy(header + 43U, "en", 2U);
    if (send(descriptor, header, sizeof(header), MSG_NOSIGNAL) != (ssize_t)sizeof(header) ||
        send(descriptor, request, request_length, MSG_NOSIGNAL) != (ssize_t)request_length ||
        send(descriptor, "", 1U, MSG_NOSIGNAL) != 1) goto failure;
    buffer = (unsigned char *)malloc(MAX_RESPONSE + 1U);
    if (buffer == NULL) goto failure;
    while (used < MAX_RESPONSE) {
        amount = recv(descriptor, buffer + used, MAX_RESPONSE - used, 0);
        if (amount <= 0) break;
        {
            unsigned char *terminator = memchr(buffer + used, 0, (size_t)amount);
            if (terminator != NULL) {
                used = (size_t)(terminator - buffer);
                found_nul = 1;
                break;
            }
        }
        used += (size_t)amount;
    }
    close(descriptor);
    if (!found_nul || used == 0U) goto failure_closed;
    buffer[used] = '\0';
    *response = buffer; *response_length = used;
    return 0;
failure:
    set_error(error, error_size, "controller unavailable");
failure_closed:
    if (error[0] == '\0') set_error(error, error_size, "controller response rejected");
    if (descriptor >= 0) close(descriptor);
    free(buffer);
    return -1;
}

static int extract_sid(const unsigned char *response, size_t length, char sid[129]) {
    const char *start, *content, *end;
    size_t amount;
    if (length == 0U || memchr(response, 0, length) != NULL) return -1;
    if (strstr((const char *)response, "<action>header</action>") == NULL) return -1;
    start = strstr((const char *)response, "<sid");
    if (start == NULL || strstr(start + 4, "<sid") != NULL) return -1;
    content = strchr(start, '>');
    if (content == NULL) return -1;
    ++content;
    end = strstr(content, "</sid>");
    if (end == NULL || strstr(end + 6, "</sid>") != NULL) return -1;
    amount = (size_t)(end - content);
    if (amount == 0U || amount > 128U || memchr(content, '&', amount) != NULL ||
        memchr(content, '<', amount) != NULL) return -1;
    memcpy(sid, content, amount); sid[amount] = '\0';
    return 0;
}

int pm3000_fetch_topology(const char *socket_path, const char *credentials_path,
                          unsigned char **response, size_t *response_length,
                          char *error, unsigned int error_size) {
    char username[129], password[257], escaped_user[650], escaped_password[1300];
    char login[MAX_REQUEST], topology[MAX_REQUEST], logout[MAX_REQUEST], sid[129];
    unsigned char *login_response = NULL, *logout_response = NULL;
    size_t login_length = 0, logout_length = 0;
    int result = -1;
    error[0] = '\0'; *response = NULL; *response_length = 0;
    if (read_credentials(credentials_path, username, password, error, error_size) != 0 ||
        xml_escape(username, escaped_user, sizeof(escaped_user)) != 0 ||
        xml_escape(password, escaped_password, sizeof(escaped_password)) != 0) goto cleanup;
    if (snprintf(login, sizeof(login),
        "<avtrans><sid/><action>login</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>units.topology</path></paths><payload><section structure=\"login\">"
        "<parameter id=\"username\" structure=\"RWtext\"><value>%s</value></parameter>"
        "<parameter id=\"password\" structure=\"password\"><value>%s</value></parameter>"
        "</section></payload></avtrans>", escaped_user, escaped_password) >= (int)sizeof(login)) goto cleanup;
    memset(password, 0, sizeof(password)); memset(escaped_password, 0, sizeof(escaped_password));
    if (exchange(socket_path, login, &login_response, &login_length, error, error_size) != 0 ||
        extract_sid(login_response, login_length, sid) != 0) {
        set_error(error, error_size, "controller login rejected"); goto cleanup;
    }
    if (snprintf(topology, sizeof(topology),
        "<avtrans><sid>%s</sid><action>get</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>units.topology</path></paths></avtrans>", sid) >= (int)sizeof(topology) ||
        snprintf(logout, sizeof(logout),
        "<avtrans><sid>%s</sid><action>logout</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>login</path></paths></avtrans>", sid) >= (int)sizeof(logout)) goto cleanup;
    if (exchange(socket_path, topology, response, response_length, error, error_size) != 0) goto logout;
    result = 0;
logout:
    if (exchange(socket_path, logout, &logout_response, &logout_length, error, error_size) != 0) {
        free(*response); *response = NULL; *response_length = 0; result = -1;
    }
cleanup:
    memset(password, 0, sizeof(password)); memset(escaped_password, 0, sizeof(escaped_password));
    free(login_response); free(logout_response);
    return result;
}
