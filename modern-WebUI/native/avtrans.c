#define _POSIX_C_SOURCE 200809L

#include "avtrans.h"
#include "controller_xml.h"
#include "projector.h"

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/un.h>
#include <unistd.h>

#define MAX_RESPONSE (1024U * 1024U)
#define MAX_REQUEST 8192U
#define MAX_ESCAPED_SID (128U * 6U + 1U)
#define MAX_ESCAPED_USERNAME (128U * 6U + 1U)
#define MAX_ESCAPED_PASSWORD (256U * 6U + 1U)

static void set_error(char *error, unsigned int size, const char *format, ...) {
    va_list arguments;
    va_start(arguments, format);
    (void)vsnprintf(error, size, format, arguments);
    va_end(arguments);
}

static void secure_zero(void *memory, size_t size) {
    volatile unsigned char *cursor = (volatile unsigned char *)memory;
    while (size-- > 0U) *cursor++ = 0U;
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

static int send_all(int descriptor, const void *data, size_t length,
                    int *request_started) {
    const unsigned char *cursor = (const unsigned char *)data;
    size_t sent = 0U;
    while (sent < length) {
        ssize_t amount = send(descriptor, cursor + sent, length - sent,
                              MSG_NOSIGNAL);
        if (amount < 0 && errno == EINTR) continue;
        if (amount <= 0) return -1;
        if (request_started != NULL) *request_started = 1;
        sent += (size_t)amount;
    }
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
    unsigned char address_bytes[16];
    unsigned char *buffer = NULL;
    const char *remote_address = getenv("REMOTE_ADDR");
    size_t used = 0;
    int found_nul = 0;
    ssize_t amount;
    size_t request_length = strlen(request);
    if (dispatched != NULL) *dispatched = 0;
    if (strlen(socket_path) >= sizeof(address.sun_path) || request_length >= MAX_REQUEST ||
        remote_address == NULL || strlen(remote_address) > 39U ||
        (inet_pton(AF_INET, remote_address, address_bytes) != 1 &&
         inet_pton(AF_INET6, remote_address, address_bytes) != 1)) goto failure;
    descriptor = socket(AF_UNIX, SOCK_STREAM, 0);
    if (descriptor < 0 || fcntl(descriptor, F_SETFD, FD_CLOEXEC) != 0) goto failure;
    (void)setsockopt(descriptor, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    (void)setsockopt(descriptor, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));
    memset(&address, 0, sizeof(address)); address.sun_family = AF_UNIX;
    strcpy(address.sun_path, socket_path);
    if (connect(descriptor, (struct sockaddr *)&address, sizeof(address)) != 0) goto failure;
    header[2] = 1U;
    memcpy(header + 3U, remote_address, strlen(remote_address));
    memcpy(header + 43U, "en", 2U);
    if (send_all(descriptor, header, sizeof(header), NULL) != 0 ||
        send_all(descriptor, request, request_length, dispatched) != 0 ||
        send_all(descriptor, "", 1U, dispatched) != 0) goto failure;
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


int pm3000_logout_session(const char *socket_path, const char *sid,
                          char *error, unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST];
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
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    free(response);
    return result;
}

int pm3000_login_session(const char *socket_path, const char *username,
                         const char *password, char sid[129],
                         unsigned char **navigation, size_t *navigation_length,
                         char *error, unsigned int error_size) {
    char escaped_user[MAX_ESCAPED_USERNAME], escaped_password[MAX_ESCAPED_PASSWORD];
    char login[MAX_REQUEST], navigation_request[MAX_REQUEST], escaped_sid[MAX_ESCAPED_SID];
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
    secure_zero(escaped_user, sizeof(escaped_user));
    secure_zero(escaped_password, sizeof(escaped_password));
    secure_zero(login, sizeof(login));
    secure_zero(navigation_request, sizeof(navigation_request));
    secure_zero(escaped_sid, sizeof(escaped_sid));
    free(login_response);
    if (result != 0) {
        free(*navigation);
        *navigation = NULL;
        *navigation_length = 0U;
        sid[0] = '\0';
    }
    return result;
}

static int fetch_session_page(const char *socket_path, const char *sid,
                              const char *page_path, unsigned char **response,
                              size_t *response_length, char *error,
                              unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST];
    int result = -1;
    error[0] = '\0';
    *response = NULL;
    *response_length = 0U;
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>get</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>%s</path></paths></avtrans>", escaped_sid, page_path) >= (int)sizeof(request))
        goto done_fetch;
    result = exchange(socket_path, request, response, response_length, error, error_size);
done_fetch:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    return result;
}

int pm3000_fetch_topology_session(const char *socket_path, const char *sid,
                                  unsigned char **response, size_t *response_length,
                                  char *error, unsigned int error_size) {
    return fetch_session_page(socket_path, sid, "units.topology", response,
                              response_length, error, error_size);
}

int pm3000_fetch_pdus_session(const char *socket_path, const char *sid,
                               unsigned char **response, size_t *response_length,
                               char *error, unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                               "units.powermanagement.pdu_management", response,
                               response_length, error, error_size);
}

int pm3000_fetch_dsview_setting_session(const char *socket_path, const char *sid,
                                         unsigned char **response,
                                         size_t *response_length, char *error,
                                         unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.applianceSettings.security.SecurityDSView",
                              response, response_length, error, error_size);
}

int pm3000_fetch_nis_setting_session(const char *socket_path, const char *sid,
                                     unsigned char **response,
                                     size_t *response_length, char *error,
                                     unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.authentication.authenticationservers.nis",
                              response, response_length, error, error_size);
}

int pm3000_fetch_sysinfo_session(const char *socket_path, const char *sid,
                                  unsigned char **response,
                                  size_t *response_length, char *error,
                                  unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.applianceSettings.information",
                              response, response_length, error, error_size);
}

int pm3000_fetch_memory_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.applianceSettings.usage.memory",
                              response, response_length, error, error_size);
}

int pm3000_fetch_flash_session(const char *socket_path, const char *sid,
                                unsigned char **response,
                                size_t *response_length, char *error,
                                unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.applianceSettings.usage.flashUsage",
                              response, response_length, error, error_size);
}

int pm3000_fetch_netdev_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.monitoring.networkmon.monitoringDevice",
                              response, response_length, error, error_size);
}

int pm3000_fetch_route4_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.monitoring.networkmon.monitoringIpv4RouteTable",
                              response, response_length, error, error_size);
}

int pm3000_fetch_route6_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.monitoring.networkmon.monitoringIpv6RouteTable",
                              response, response_length, error, error_size);
}

int pm3000_fetch_serial_session(const char *socket_path, const char *sid,
                                 unsigned char **response,
                                 size_t *response_length, char *error,
                                 unsigned int error_size) {
    return fetch_session_page(socket_path, sid,
                              "units.monitoring.serialstatistics",
                              response, response_length, error, error_size);
}

int pm3000_fetch_fixed_setting_session(const char *socket_path, const char *sid,
                                        const char *path,
                                        unsigned char **response,
                                        size_t *response_length, char *error,
                                        unsigned int error_size) {
    return fetch_session_page(socket_path, sid, path, response, response_length,
                              error, error_size);
}

int pm3000_save_fixed_setting_session(const char *socket_path, const char *sid,
                                       const char *path, const char *form_payload,
                                       unsigned char **response,
                                       size_t *response_length, char *error,
                                       unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST];
    int dispatched = 0, result = -1;
    error[0] = '\0';
    *response = NULL;
    *response_length = 0U;
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>save</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>%s</path></paths><payload>%s</payload></avtrans>",
                 escaped_sid, path, form_payload) >= (int)sizeof(request)) goto done_fixed;
    if (exchange_internal(socket_path, request, response, response_length,
                          &dispatched, error, error_size) != 0) {
        result = dispatched ? 3 : -1;
        goto done_fixed;
    }
    result = 0;
done_fixed:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    return result;
}

int pm3000_apply_outlet_action_session(const char *socket_path, const char *sid,
                                       const char *outlet_id, const char *revision,
                                       const char *action, char *error,
                                       unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST], identity[256], escaped_identity[1300];
    unsigned char *topology = NULL, *response = NULL;
    size_t topology_length = 0U, response_length = 0U;
    int resolution, result = -1;
    const char *controller_action;
    error[0] = '\0';
    if (strcmp(action, "on") == 0) controller_action = "targPowerOn";
    else if (strcmp(action, "off") == 0) controller_action = "targPowerOff";
    else if (strcmp(action, "cycle") == 0) controller_action = "targCycle";
    else controller_action = NULL;
    if (controller_action == NULL ||
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
                 escaped_sid, controller_action, escaped_identity) >= (int)sizeof(request))
        goto done;
    {
        int dispatched = 0;
        if (exchange_internal(socket_path, request, &response, &response_length,
                              &dispatched, error, error_size) != 0) {
            result = dispatched ? 3 : -1;
            goto done;
        }
    }
    if (pm3000_confirm_outlet_action(response, (unsigned long)response_length,
                                     identity, action) != 0) {
        set_error(error, error_size, "controller action outcome unknown");
        result = 3;
        goto done;
    }
    result = 0;
done:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    secure_zero(identity, sizeof(identity));
    secure_zero(escaped_identity, sizeof(escaped_identity));
    free(topology);
    free(response);
    return result;
}

int pm3000_apply_pdu_action_session(const char *socket_path, const char *sid,
                                    const char *pdu_id, const char *revision,
                                    const char *action, char *error,
                                    unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST], identity[256], escaped_identity[1300];
    unsigned char *pdus = NULL, *response = NULL;
    size_t pdus_length = 0U, response_length = 0U;
    int resolution, dispatched = 0, result = -1;
    error[0] = '\0';
    if ((strcmp(action, "on") != 0 && strcmp(action, "off") != 0 && strcmp(action, "cycle") != 0) ||
        pm3000_fetch_pdus_session(socket_path, sid, &pdus, &pdus_length,
                                  error, error_size) != 0) goto done_pdu;
    resolution = pm3000_resolve_pdu_identity(pdus, (unsigned long)pdus_length,
                                              pdu_id, revision, identity,
                                              sizeof(identity), error, error_size);
    if (resolution != 0) { result = resolution; goto done_pdu; }
    if (xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        xml_escape(identity, escaped_identity, sizeof(escaped_identity)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>%s</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units.powermanagement.pdu_management</path></paths><payload>"
                 "<section structure=\"table\" id=\"pdu_devices_table\"><array id=\"%s\"></array>"
                 "</section></payload></avtrans>", escaped_sid, action, escaped_identity) >= (int)sizeof(request))
        goto done_pdu;
    if (exchange_internal(socket_path, request, &response, &response_length, &dispatched,
                          error, error_size) != 0) {
        result = dispatched ? 3 : -1; goto done_pdu;
    }
    if (pm3000_confirm_pdu_action(response, (unsigned long)response_length,
                                  identity, action) != 0) {
        set_error(error, error_size, "controller PDU action outcome unknown");
        result = 3; goto done_pdu;
    }
    result = 0;
done_pdu:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    secure_zero(identity, sizeof(identity));
    secure_zero(escaped_identity, sizeof(escaped_identity));
    free(pdus); free(response);
    return result;
}

int pm3000_change_password_session(const char *socket_path, const char *sid,
                                   const char *old_password,
                                   const char *new_password,
                                   const char *confirmation,
                                   char *error, unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], escaped_old[MAX_ESCAPED_PASSWORD],
         escaped_new[MAX_ESCAPED_PASSWORD], escaped_confirmation[MAX_ESCAPED_PASSWORD],
         request[MAX_REQUEST];
    unsigned char *response = NULL;
    size_t response_length = 0U;
    int dispatched = 0, result = -1;
    error[0] = '\0';
    memset(escaped_old, 0, sizeof(escaped_old));
    memset(escaped_new, 0, sizeof(escaped_new));
    memset(escaped_confirmation, 0, sizeof(escaped_confirmation));
    memset(request, 0, sizeof(request));
    if (old_password[0] == '\0' || new_password[0] == '\0' ||
        strcmp(new_password, confirmation) != 0 ||
        xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        xml_escape(old_password, escaped_old, sizeof(escaped_old)) != 0 ||
        xml_escape(new_password, escaped_new, sizeof(escaped_new)) != 0 ||
        xml_escape(confirmation, escaped_confirmation,
                   sizeof(escaped_confirmation)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>save</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>units.change_password</path></paths><payload><section structure=\"form\">"
                 "<parameter id=\"oldpassword\" structure=\"password\"><value>%s</value></parameter>"
                 "<parameter id=\"newpassword\" structure=\"password\"><value>%s</value></parameter>"
                 "<parameter id=\"confirmpassword\" structure=\"password\"><value>%s</value></parameter>"
                 "</section></payload></avtrans>", escaped_sid, escaped_old,
                 escaped_new, escaped_confirmation) >= (int)sizeof(request))
        goto done_password;
    if (exchange_internal(socket_path, request, &response, &response_length,
                          &dispatched, error, error_size) != 0) {
        result = dispatched ? 3 : -1;
        goto done_password;
    }
    if (!pm3000_xml_password_changed(response, response_length)) {
        set_error(error, error_size, "controller password outcome unknown");
        result = 3;
        goto done_password;
    }
    result = 0;
done_password:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(escaped_old, sizeof(escaped_old));
    secure_zero(escaped_new, sizeof(escaped_new));
    secure_zero(escaped_confirmation, sizeof(escaped_confirmation));
    secure_zero(request, sizeof(request));
    free(response);
    return result;
}

int pm3000_save_dsview_setting_session(const char *socket_path, const char *sid,
                                       int allow_dsview, char *error,
                                       unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], request[MAX_REQUEST];
    unsigned char *response = NULL;
    size_t response_length = 0U;
    int dispatched = 0, result = -1;
    static const char path[] = "units.applianceSettings.security.SecurityDSView";
    error[0] = '\0';
    if ((allow_dsview != 0 && allow_dsview != 1) ||
        xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>save</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>%s</path></paths><payload><section structure=\"form\">"
                 "<parameter id=\"allowDSView\" structure=\"checkbox\"><value>%s</value></parameter>"
                 "</section></payload></avtrans>", escaped_sid, path,
                 allow_dsview ? "true" : "false") >= (int)sizeof(request))
        goto done_dsview;
    if (exchange_internal(socket_path, request, &response, &response_length,
                          &dispatched, error, error_size) != 0) {
        result = dispatched ? 3 : -1;
        goto done_dsview;
    }
    {
        int confirmed = 0;
        if (pm3000_xml_dsview_value(response, response_length, path,
                                     &confirmed) != 0 ||
            confirmed != allow_dsview) {
            set_error(error, error_size, "controller did not confirm the DSView setting");
            result = 3;
            goto done_dsview;
        }
    }
    result = 0;
done_dsview:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(request, sizeof(request));
    free(response);
    return result;
}

int pm3000_save_nis_setting_session(const char *socket_path, const char *sid,
                                    const char *domain_name,
                                    const char *address, char *error,
                                    unsigned int error_size) {
    char escaped_sid[MAX_ESCAPED_SID], escaped_domain[512], escaped_address[512];
    char request[MAX_REQUEST];
    unsigned char *response = NULL;
    size_t response_length = 0U;
    int dispatched = 0, result = -1;
    static const char path[] = "units.authentication.authenticationservers.nis";
    error[0] = '\0';
    if (sid == NULL || domain_name == NULL || address == NULL ||
        domain_name[0] == '\0' || address[0] == '\0' ||
        strlen(domain_name) >= 100U || strlen(address) >= 100U ||
        xml_escape(sid, escaped_sid, sizeof(escaped_sid)) != 0 ||
        xml_escape(domain_name, escaped_domain, sizeof(escaped_domain)) != 0 ||
        xml_escape(address, escaped_address, sizeof(escaped_address)) != 0 ||
        snprintf(request, sizeof(request),
                 "<avtrans><sid>%s</sid><action>save</action><agents><src>wmi</src><dest>controller</dest></agents>"
                 "<paths><path>%s</path></paths><payload><section structure=\"form\">"
                 "<parameter id=\"domainname\" structure=\"text\"><value>%s</value></parameter>"
                 "<parameter id=\"address\" structure=\"text\"><value>%s</value></parameter>"
                 "</section></payload></avtrans>", escaped_sid, path,
                 escaped_domain, escaped_address) >= (int)sizeof(request))
        goto done_nis;
    if (exchange_internal(socket_path, request, &response, &response_length,
                          &dispatched, error, error_size) != 0) {
        result = dispatched ? 3 : -1;
        goto done_nis;
    }
    {
        char confirmed_domain[100], confirmed_address[100];
        if (pm3000_xml_nis_values(response, response_length, path,
                                   confirmed_domain, sizeof(confirmed_domain),
                                   confirmed_address, sizeof(confirmed_address)) != 0 ||
            strcmp(confirmed_domain, domain_name) != 0 ||
            strcmp(confirmed_address, address) != 0) {
            set_error(error, error_size, "controller did not confirm the NIS setting");
            result = 3;
            goto done_nis;
        }
    }
    result = 0;
done_nis:
    secure_zero(escaped_sid, sizeof(escaped_sid));
    secure_zero(escaped_domain, sizeof(escaped_domain));
    secure_zero(escaped_address, sizeof(escaped_address));
    secure_zero(request, sizeof(request));
    free(response);
    return result;
}
