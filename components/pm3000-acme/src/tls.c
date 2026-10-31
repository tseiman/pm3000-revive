#define _POSIX_C_SOURCE 200112L

#include "pm3000_acme_tls.h"
#include "openssl_ssl_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#define SSL_VERIFY_PEER_VALUE 1
#define SSL_CTRL_SET_TLSEXT_HOSTNAME 55
#define TLSEXT_NAMETYPE_HOST_NAME 0
#define X509_V_OK_VALUE 0L
#define NID_SUBJECT_ALT_NAME 85
#define GEN_DNS_VALUE 2

#ifdef PM3000_FIRMWARE_ABI
struct pm3000_kernel_timeval {
    signed int tv_sec;
    signed int tv_usec;
};
typedef char pm3000_kernel_timeval_must_be_8_bytes[
    sizeof(struct pm3000_kernel_timeval) == 8U ? 1 : -1];
/* Linux 2.6 PPC socket.h values; musl time64 exposes incompatible 66/67. */
#define PM3000_SO_RCVTIMEO 18
#define PM3000_SO_SNDTIMEO 19
#else
#define pm3000_kernel_timeval timeval
#define PM3000_SO_RCVTIMEO SO_RCVTIMEO
#define PM3000_SO_SNDTIMEO SO_SNDTIMEO
#endif

static int dns_pattern_matches(const unsigned char *pattern,
                               unsigned int pattern_length,
                               const char *hostname)
{
    char normalized[PM3000_ACME_HOST_MAX + 1U];
    char certificate_name[PM3000_ACME_HOST_MAX + 1U];
    unsigned int index;
    unsigned int first_dot = 0U;
    if (pattern_length == 0U || pattern_length > PM3000_ACME_HOST_MAX ||
        pm3000_acme_dns_name_normalize(hostname, normalized,
                                       sizeof(normalized)) !=
            PM3000_ACME_URL_OK) return 0;
    for (index = 0U; index < pattern_length; ++index) {
        unsigned char value = pattern[index];
        if (value == 0U || value > 0x7fU) return 0;
        certificate_name[index] = (char)value;
    }
    certificate_name[pattern_length] = '\0';
    if (pattern_length > 2U && certificate_name[0] == '*' &&
        certificate_name[1] == '.') {
        if (pm3000_acme_dns_name_normalize(
                certificate_name + 2, certificate_name + 2,
                sizeof(certificate_name) - 2U) != PM3000_ACME_URL_OK) return 0;
        for (index = 0U; normalized[index] != '\0'; ++index) {
            if (normalized[index] == '.') {
                first_dot = index;
                break;
            }
        }
        if (first_dot == 0U) return 0;
        index = 0U;
        while (normalized[first_dot + 1U + index] != '\0' &&
               certificate_name[2U + index] != '\0') {
            if (normalized[first_dot + 1U + index] !=
                certificate_name[2U + index]) return 0;
            ++index;
        }
        return normalized[first_dot + 1U + index] == '\0' &&
               certificate_name[2U + index] == '\0';
    }
    if (pm3000_acme_dns_name_normalize(
            certificate_name, certificate_name,
            sizeof(certificate_name)) != PM3000_ACME_URL_OK) return 0;
    return strcmp(certificate_name, normalized) == 0;
}

static int certificate_hostname(X509 *certificate, const char *hostname)
{
    OPENSSL_STACK *names;
    int count;
    int index;
    int matched = 0;
    if (certificate == (X509 *)0 || hostname == (const char *)0) return 0;
    names = (OPENSSL_STACK *)X509_get_ext_d2i(
        certificate, NID_SUBJECT_ALT_NAME, (int *)0, (int *)0);
    if (names == (OPENSSL_STACK *)0) return 0;
    count = PM3000_SK_NUM(names);
    if (count <= 0 || count > 64) {
        GENERAL_NAMES_free(names);
        return 0;
    }
    for (index = 0; index < count; ++index) {
        GENERAL_NAME *name = (GENERAL_NAME *)PM3000_SK_VALUE(names, index);
        int type = -1;
        const ASN1_STRING *value = (const ASN1_STRING *)
            GENERAL_NAME_get0_value(name, &type);
        int length;
        unsigned char *bytes;
        if (type != GEN_DNS_VALUE) continue;
        if (value == (const ASN1_STRING *)0 ||
            (length = ASN1_STRING_length(value)) <= 0 ||
            length > (int)PM3000_ACME_HOST_MAX) {
            matched = 0;
            break;
        }
        bytes = ASN1_STRING_data((ASN1_STRING *)value);
        if (bytes == (unsigned char *)0 ||
            !dns_pattern_matches(bytes, (unsigned int)length, hostname)) {
            continue;
        }
        matched = 1;
        break;
    }
    GENERAL_NAMES_free(names);
    return matched;
}

int pm3000_acme_tls_certificate_file_matches(const char *certificate_path,
                                              const char *hostname)
{
    BIO *bio;
    X509 *certificate;
    int result;
    if (certificate_path == (const char *)0 || hostname == (const char *)0)
        return PM3000_ACME_TLS_INVALID;
    bio = BIO_new_file(certificate_path, "r");
    if (bio == (BIO *)0) return PM3000_ACME_TLS_IO;
    certificate = PEM_read_bio_X509(bio, (X509 **)0, (void *)0, (void *)0);
    BIO_free(bio);
    if (certificate == (X509 *)0) return PM3000_ACME_TLS_INVALID;
    result = certificate_hostname(certificate, hostname);
    X509_free(certificate);
    return result ? PM3000_ACME_TLS_OK : PM3000_ACME_TLS_HOSTNAME;
}

static int tcp_connect(const char *hostname, unsigned int port,
                       unsigned int timeout_seconds)
{
    struct addrinfo hints;
    struct addrinfo *addresses = (struct addrinfo *)0;
    struct addrinfo *address;
    char service[6];
    int descriptor = -1;
    int length;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    length = snprintf(service, sizeof(service), "%u", port);
    if (length <= 0 || (unsigned int)length >= sizeof(service) ||
        getaddrinfo(hostname, service, &hints, &addresses) != 0)
        return -1;
    for (address = addresses; address != (struct addrinfo *)0;
         address = address->ai_next) {
        int flags;
        int connected;
        descriptor = socket(address->ai_family, address->ai_socktype,
                            address->ai_protocol);
        if (descriptor < 0) continue;
        flags = fcntl(descriptor, F_GETFL, 0);
        if (flags < 0 || fcntl(descriptor, F_SETFL, flags | O_NONBLOCK) < 0) {
            close(descriptor); descriptor = -1; continue;
        }
        connected = connect(descriptor, address->ai_addr,
                            address->ai_addrlen);
        if (connected < 0 && errno == EINPROGRESS) {
            struct pollfd wait_fd;
            int wait_result;
            int socket_error = 0;
            socklen_t error_length = sizeof(socket_error);
            wait_fd.fd = descriptor;
            wait_fd.events = POLLOUT;
            wait_fd.revents = 0;
            wait_result = poll(&wait_fd, 1,
                               timeout_seconds > 2147483U ? 2147483000 :
                               (int)(timeout_seconds * 1000U));
            if (wait_result == 1 &&
                getsockopt(descriptor, SOL_SOCKET, SO_ERROR, &socket_error,
                           &error_length) == 0 && socket_error == 0) {
                connected = 0;
            }
        }
        if (connected == 0 &&
            fcntl(descriptor, F_SETFL, flags) == 0) break;
        close(descriptor);
        descriptor = -1;
    }
    freeaddrinfo(addresses);
    if (descriptor >= 0) {
        struct pm3000_kernel_timeval timeout;
        timeout.tv_sec = (signed int)timeout_seconds;
        timeout.tv_usec = 0;
        if (setsockopt(descriptor, SOL_SOCKET, PM3000_SO_RCVTIMEO, &timeout,
                       sizeof(timeout)) != 0 ||
            setsockopt(descriptor, SOL_SOCKET, PM3000_SO_SNDTIMEO, &timeout,
                       sizeof(timeout)) != 0) {
            close(descriptor);
            descriptor = -1;
        }
    }
    return descriptor;
}

void pm3000_acme_tls_close(struct pm3000_acme_tls_connection *connection)
{
    if (connection == (struct pm3000_acme_tls_connection *)0) return;
    if (connection->session != (void *)0) {
        SSL_shutdown((SSL *)connection->session);
        SSL_free((SSL *)connection->session);
    }
    if (connection->context != (void *)0)
        SSL_CTX_free((SSL_CTX *)connection->context);
    if (connection->socket_fd >= 0) close(connection->socket_fd);
    connection->context = (void *)0;
    connection->session = (void *)0;
    connection->socket_fd = -1;
}

int pm3000_acme_tls_connect(const struct pm3000_acme_url *url,
                            const char *ca_file,
                            unsigned int timeout_seconds,
                            struct pm3000_acme_tls_connection *connection)
{
    SSL_CTX *context;
    SSL *session;
    X509 *certificate;
    int descriptor;
    int result = PM3000_ACME_TLS_NETWORK;
    if (url == (const struct pm3000_acme_url *)0 ||
        ca_file == (const char *)0 ||
        connection == (struct pm3000_acme_tls_connection *)0 ||
        timeout_seconds == 0U || timeout_seconds > 300U)
        return PM3000_ACME_TLS_INVALID;
    connection->context = (void *)0;
    connection->session = (void *)0;
    connection->socket_fd = -1;
    if (!PM3000_SSL_GLOBAL_INIT()) return PM3000_ACME_TLS_INVALID;
    descriptor = tcp_connect(url->host, url->port, timeout_seconds);
    if (descriptor < 0) return PM3000_ACME_TLS_NETWORK;
    context = SSL_CTX_new(TLSv1_2_client_method());
    if (context == (SSL_CTX *)0) {
        close(descriptor);
        return PM3000_ACME_TLS_INVALID;
    }
    SSL_CTX_set_verify(context, SSL_VERIFY_PEER_VALUE,
                       (int (*)(int, void *))0);
    if (!SSL_CTX_load_verify_locations(context, ca_file, (const char *)0)) {
        SSL_CTX_free(context);
        close(descriptor);
        return PM3000_ACME_TLS_TRUST;
    }
    session = SSL_new(context);
    if (session == (SSL *)0 ||
        !SSL_set_fd(session, descriptor) ||
        SSL_ctrl(session, SSL_CTRL_SET_TLSEXT_HOSTNAME,
                 TLSEXT_NAMETYPE_HOST_NAME, (void *)url->host) != 1L ||
        SSL_connect(session) != 1) {
        if (session != (SSL *)0) SSL_free(session);
        SSL_CTX_free(context);
        close(descriptor);
        return PM3000_ACME_TLS_NETWORK;
    }
    if (SSL_get_verify_result(session) != X509_V_OK_VALUE) {
        result = PM3000_ACME_TLS_TRUST;
        goto rejected;
    }
    certificate = PM3000_SSL_GET_PEER_CERTIFICATE(session);
    if (certificate == (X509 *)0 ||
        !certificate_hostname(certificate, url->host)) {
        if (certificate != (X509 *)0) X509_free(certificate);
        result = PM3000_ACME_TLS_HOSTNAME;
        goto rejected;
    }
    X509_free(certificate);
    connection->context = context;
    connection->session = session;
    connection->socket_fd = descriptor;
    return PM3000_ACME_TLS_OK;

rejected:
    SSL_free(session);
    SSL_CTX_free(context);
    close(descriptor);
    return result;
}

int pm3000_acme_tls_write_all(struct pm3000_acme_tls_connection *connection,
                              const unsigned char *data,
                              unsigned int length)
{
    unsigned int offset = 0U;
    if (connection == (struct pm3000_acme_tls_connection *)0 ||
        connection->session == (void *)0 || data == (const unsigned char *)0)
        return PM3000_ACME_TLS_INVALID;
    while (offset < length) {
        unsigned int remaining = length - offset;
        int amount = SSL_write((SSL *)connection->session, data + offset,
                               remaining > 2147483647U ? 2147483647 :
                               (int)remaining);
        if (amount <= 0) return PM3000_ACME_TLS_IO;
        offset += (unsigned int)amount;
    }
    return PM3000_ACME_TLS_OK;
}

int pm3000_acme_tls_read(struct pm3000_acme_tls_connection *connection,
                         unsigned char *output, unsigned int capacity,
                         unsigned int *amount)
{
    int received;
    if (amount != (unsigned int *)0) *amount = 0U;
    if (connection == (struct pm3000_acme_tls_connection *)0 ||
        connection->session == (void *)0 || output == (unsigned char *)0 ||
        amount == (unsigned int *)0 || capacity == 0U ||
        capacity > 2147483647U) return PM3000_ACME_TLS_INVALID;
    received = SSL_read((SSL *)connection->session, output, (int)capacity);
    if (received == 0) return PM3000_ACME_TLS_EOF;
    if (received < 0) return PM3000_ACME_TLS_IO;
    *amount = (unsigned int)received;
    return PM3000_ACME_TLS_OK;
}
