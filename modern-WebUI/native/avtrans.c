#define _POSIX_C_SOURCE 200809L

#include "avtrans.h"
#include "controller_xml.h"
#include "projector.h"

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

static int exchange_internal(const char *socket_path, const char *request,
                             unsigned char **response, size_t *response_length,
                             int *dispatched, char *error,
                             unsigned int error_size) {
    int descriptor = -1;
    struct sockaddr_un address;
    struct timeval timeout = {3, 0};
    unsigned char header[59] = {0};
    unsigned char *buffer = NULL;
    size_t used = 0;
    int found_nul = 0;
    ssize_t amount;
    size_t request_length = strlen(request);
    if (dispatched != NULL) *dispatched = 0;
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
    if (dispatched != NULL) *dispatched = 1;
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

static int exchange(const char *socket_path, const char *request,
                    unsigned char **response, size_t *response_length,
                    char *error, unsigned int error_size) {
    return exchange_internal(socket_path, request, response, response_length,
                             NULL, error, error_size);
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
        pm3000_xml_login_sid(login_response, login_length, sid) != 0) {
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
    if (exchange(socket_path, logout, &logout_response, &logout_length,
                 error, error_size) != 0 ||
        !pm3000_xml_confirm(logout_response, logout_length, "login", "login")) {
        free(*response); *response = NULL; *response_length = 0; result = -1;
    }
cleanup:
    memset(password, 0, sizeof(password)); memset(escaped_password, 0, sizeof(escaped_password));
    free(login_response); free(logout_response);
    return result;
}

int pm3000_apply_outlet_action(const char *socket_path, const char *credentials_path,
                               const char *outlet_id, const char *revision,
                               const char *action, char *error,
                               unsigned int error_size) {
    char username[129], password[257], escaped_user[650], escaped_password[1300];
    char login[MAX_REQUEST] = {0}, topology[MAX_REQUEST] = {0};
    char request[MAX_REQUEST] = {0}, logout[MAX_REQUEST] = {0};
    char sid[129], identity[256], escaped_identity[1300];
    unsigned char *login_response = NULL, *topology_response = NULL;
    unsigned char *action_response = NULL, *logout_response = NULL;
    size_t login_length = 0, topology_length = 0, action_length = 0, logout_length = 0;
    int result = -1, resolution;
    error[0] = '\0';
    set_error(error, error_size, "outlet action contract unverified");
    return -1;
    if ((strcmp(action, "on") != 0 && strcmp(action, "off") != 0 && strcmp(action, "cycle") != 0) ||
        read_credentials(credentials_path, username, password, error, error_size) != 0 ||
        xml_escape(username, escaped_user, sizeof(escaped_user)) != 0 ||
        xml_escape(password, escaped_password, sizeof(escaped_password)) != 0) goto cleanup_action;
    if (snprintf(login, sizeof(login),
        "<avtrans><sid/><action>login</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>units.topology</path></paths><payload><section structure=\"login\">"
        "<parameter id=\"username\" structure=\"RWtext\"><value>%s</value></parameter>"
        "<parameter id=\"password\" structure=\"password\"><value>%s</value></parameter>"
        "</section></payload></avtrans>", escaped_user, escaped_password) >= (int)sizeof(login)) goto cleanup_action;
    memset(password, 0, sizeof(password)); memset(escaped_password, 0, sizeof(escaped_password));
    if (exchange(socket_path, login, &login_response, &login_length, error, error_size) != 0 ||
        pm3000_xml_login_sid(login_response, login_length, sid) != 0) {
        set_error(error, error_size, "controller login rejected"); goto cleanup_action;
    }
    if (snprintf(topology, sizeof(topology),
        "<avtrans><sid>%s</sid><action>get</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>units.topology</path></paths></avtrans>", sid) >= (int)sizeof(topology) ||
        snprintf(logout, sizeof(logout),
        "<avtrans><sid>%s</sid><action>logout</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>login</path></paths></avtrans>", sid) >= (int)sizeof(logout)) goto logout_action;
    if (exchange(socket_path, topology, &topology_response, &topology_length, error, error_size) != 0) goto logout_action;
    resolution = pm3000_resolve_outlet_identity(topology_response, (unsigned long)topology_length,
                                                 outlet_id, revision, identity, sizeof(identity),
                                                 error, error_size);
    if (resolution != 0) { result = resolution == 2 ? 2 : resolution == 1 ? 1 : -1; goto logout_action; }
    if (xml_escape(identity, escaped_identity, sizeof(escaped_identity)) != 0 ||
        snprintf(request, sizeof(request),
        "<avtrans><sid>%s</sid><action>%s</action><agents><src>wmi</src><dest>controller</dest></agents>"
        "<paths><path>units.topology</path></paths><payload><section structure=\"table\" id=\"topologyTable\">"
        "<array id=\"%s\"></array></section></payload></avtrans>", sid, action, escaped_identity) >= (int)sizeof(request)) goto logout_action;
    {
        int dispatched = 0;
        if (exchange_internal(socket_path, request, &action_response, &action_length,
                              &dispatched, error, error_size) != 0) {
            result = dispatched ? 3 : -1;
            goto logout_action;
        }
    }
    if (!pm3000_xml_confirm(action_response, action_length, action,
                            "units.topology")) {
        set_error(error, error_size, "controller action outcome unknown");
        result = 3;
        goto logout_action;
    }
    result = 0;
logout_action:
    if (logout[0] == '<')
        (void)exchange(socket_path, logout, &logout_response, &logout_length,
                       error, error_size);
cleanup_action:
    memset(password, 0, sizeof(password)); memset(escaped_password, 0, sizeof(escaped_password));
    free(login_response); free(topology_response); free(action_response); free(logout_response);
    return result;
}

int pm3000_logout_session(const char *socket_path, const char *sid,
                          char *error, unsigned int error_size) {
    char escaped_sid[650], request[MAX_REQUEST];
    unsigned char *response = NULL;
    size_t response_length = 0U;
    int result = -1;
    error[0] = '\0';
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>logout</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>login</path></paths></avtrans>", escaped_sid) >= (int)sizeof(request))
        goto done;
    if (exchange(socket_path, request, &response, &response_length, error, error_size) == 0 &&
        pm3000_xml_confirm(response, response_length, "login", "login")) result = 0;
done:
    free(response);
    return result;
}

int pm3000_login_session(const char *socket_path, const char *username,
                         const char *password, char sid[129],
                         unsigned char **navigation, size_t *navigation_length,
                         char *error, unsigned int error_size) {
    char escaped_user[650], escaped_password[1300];
    char login[MAX_REQUEST], navigation_request[MAX_REQUEST], escaped_sid[650];
    unsigned char *login_response = NULL;
    size_t login_length = 0U;
    int result = -1;
    error[0] = '\0';
    *navigation = NULL;
    *navigation_length = 0U;
    sid[0] = '\0';
    memset(login, 0, sizeof(login));
    memset(escaped_password, 0, sizeof(escaped_password));
    if (xml_escape(username, escaped_user, sizeof(escaped_user)) != 0 ||
        xml_escape(password, escaped_password, sizeof(escaped_password)) != 0 ||
        snprintf(login, sizeof(login),
                 "<avtrans><sid/><action>login</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units.topology</path></paths><payload><section structure=\"login\">"
                 "<parameter id=\"username\" structure=\"RWtext\"><value>%s</value></parameter>"
                 "<parameter id=\"password\" structure=\"password\"><value>%s</value></parameter>"
                 "</section></payload></avtrans>", escaped_user, escaped_password) >= (int)sizeof(login))
        goto done;
    if (exchange(socket_path, login, &login_response, &login_length, error, error_size) != 0 ||
        pm3000_xml_login_sid(login_response, login_length, sid) != 0 ||
        xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0) {
        set_error(error, error_size, "controller login rejected");
        goto done;
    }
    memset(login, 0, sizeof(login));
    memset(escaped_password, 0, sizeof(escaped_password));
    if (snprintf(navigation_request, sizeof(navigation_request),
                 "<avtrans><sid>%s</sid><action>navigation</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units</path></paths></avtrans>", escaped_sid) >= (int)sizeof(navigation_request) ||
        exchange(socket_path, navigation_request, navigation, navigation_length,
                 error, error_size) != 0) {
        (void)pm3000_logout_session(socket_path, sid, error, error_size);
        goto done;
    }
    result = 0;
done:
    memset(login, 0, sizeof(login));
    memset(escaped_password, 0, sizeof(escaped_password));
    free(login_response);
    if (result != 0) {
        free(*navigation);
        *navigation = NULL;
        *navigation_length = 0U;
        sid[0] = '\0';
    }
    return result;
}

int pm3000_fetch_topology_session(const char *socket_path, const char *sid,
                                  unsigned char **response, size_t *response_length,
                                  char *error, unsigned int error_size) {
    char escaped_sid[650], request[MAX_REQUEST];
    error[0] = '\0';
    *response = NULL;
    *response_length = 0U;
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>get</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units.topology</path></paths></avtrans>", escaped_sid) >= (int)sizeof(request))
        return -1;
    return exchange(socket_path, request, response, response_length, error, error_size);
}

int pm3000_apply_outlet_action_session(const char *socket_path, const char *sid,
                                       const char *outlet_id, const char *revision,
                                       const char *action, char *error,
                                       unsigned int error_size) {
    char escaped_sid[650], request[MAX_REQUEST], identity[256], escaped_identity[1300];
    unsigned char *topology = NULL, *response = NULL;
    size_t topology_length = 0U, response_length = 0U;
    int resolution, result = -1;
    error[0] = '\0';
    set_error(error, error_size, "outlet action contract unverified");
    return -1;
    if ((strcmp(action, "on") != 0 && strcmp(action, "off") != 0 && strcmp(action, "cycle") != 0) ||
        pm3000_fetch_topology_session(socket_path, sid, &topology, &topology_length,
                                      error, error_size) != 0) goto done;
    resolution = pm3000_resolve_outlet_identity(topology, (unsigned long)topology_length,
                                                 outlet_id, revision, identity,
                                                 sizeof(identity), error, error_size);
    if (resolution != 0) { result = resolution == 2 ? 2 : resolution == 1 ? 1 : -1; goto done; }
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        xml_escape(identity, escaped_identity, sizeof(escaped_identity)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>%s</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units.topology</path></paths><payload><section structure=\"table\" id=\"topologyTable\">"
                 "<array id=\"%s\"></array></section></payload></avtrans>",
                 escaped_sid, action, escaped_identity) >= (int)sizeof(request))
        goto done;
    {
        int dispatched = 0;
        if (exchange_internal(socket_path, request, &response, &response_length,
                              &dispatched, error, error_size) != 0) {
            result = dispatched ? 3 : -1;
            goto done;
        }
    }
    if (!pm3000_xml_confirm(response, response_length, action,
                            "units.topology")) {
        set_error(error, error_size, "controller action outcome unknown");
        result = 3;
        goto done;
    }
    result = 0;
done:
    free(topology);
    free(response);
    return result;
}
