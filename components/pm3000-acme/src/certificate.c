#include "pm3000_acme_certificate.h"
#include "pm3000_acme_tls.h"
#include "pm3000_acme_url.h"
#include "openssl_compat.h"
#include "openssl_ssl_compat.h"

#include <stdio.h>
#include <string.h>

#define CERTIFICATE_NAMES_MAX 16U
#define CERTIFICATE_CHAIN_MAX 8U
#define CERTIFICATE_FILE_MAX PM3000_ACME_CA_BUNDLE_MAX
#define NID_SUBJECT_ALT_NAME 85
#define GEN_DNS_VALUE 2

static unsigned char certificate_file[CERTIFICATE_FILE_MAX + 1U];

static int pem_base64(unsigned char value)
{
    return (value >= 'A' && value <= 'Z') ||
           (value >= 'a' && value <= 'z') ||
           (value >= '0' && value <= '9') || value == '+' || value == '/' ||
           value == '=';
}

static int pem_marker(const unsigned char *data, unsigned int length)
{
    static const char begin[] = "-----BEGIN";
    static const char end[] = "-----END";
    unsigned int index;
    for (index = 0U; index < length; ++index) {
        if ((length - index >= sizeof(begin) - 1U &&
             memcmp(data + index, begin, sizeof(begin) - 1U) == 0) ||
            (length - index >= sizeof(end) - 1U &&
             memcmp(data + index, end, sizeof(end) - 1U) == 0))
            return 1;
    }
    return 0;
}

static int pem_line(const unsigned char *data, unsigned int length,
                    unsigned int index, unsigned int *content_length,
                    unsigned int *next)
{
    unsigned int end = index;
    while (end < length && data[end] != '\r' && data[end] != '\n') ++end;
    *content_length = end - index;
    if (end == length) {
        *next = end;
        return 1;
    }
    if (data[end] == '\r') {
        if (end + 1U >= length || data[end + 1U] != '\n') return 0;
        *next = end + 2U;
    } else {
        *next = end + 1U;
    }
    return 1;
}

static int strict_pem_count(const unsigned char *data, unsigned int length,
                            unsigned int *count, int allow_text)
{
    static const char begin[] = "-----BEGIN CERTIFICATE-----";
    static const char end[] = "-----END CERTIFICATE-----";
    unsigned int index = 0U;
    unsigned int blocks = 0U;
    int in_certificate = 0;
    unsigned int payload = 0U;
    if (data == (const unsigned char *)0 || count == (unsigned int *)0 ||
        length == 0U || length > CERTIFICATE_FILE_MAX) return 0;
    while (index < length) {
        unsigned int line_length;
        unsigned int next;
        unsigned int item;
        if (!pem_line(data, length, index, &line_length, &next)) return 0;
        if (!in_certificate) {
            if (line_length == sizeof(begin) - 1U &&
                memcmp(data + index, begin, sizeof(begin) - 1U) == 0) {
                in_certificate = 1;
                payload = 0U;
            } else {
                if (pem_marker(data + index, line_length)) return 0;
                for (item = 0U; item < line_length; ++item) {
                    unsigned char value = data[index + item];
                    if (value != '\t' && (value < 0x20U || value > 0x7eU))
                        return 0;
                    if (!allow_text && value != ' ' && value != '\t')
                        return 0;
                }
            }
        } else if (line_length == sizeof(end) - 1U &&
                   memcmp(data + index, end, sizeof(end) - 1U) == 0) {
            if (payload < 4U || ++blocks > CERTIFICATE_CHAIN_MAX + 1U)
                return 0;
            in_certificate = 0;
        } else {
            if (pem_marker(data + index, line_length)) return 0;
            for (item = 0U; item < line_length; ++item) {
                if (pem_base64(data[index + item])) ++payload;
                else if (data[index + item] != ' ' &&
                         data[index + item] != '\t')
                    return 0;
            }
        }
        index = next;
    }
    if (in_certificate || blocks == 0U) return 0;
    *count = blocks;
    return 1;
}

int pm3000_acme_certificate_validate_ca_bundle(
    const unsigned char *bundle, unsigned int bundle_length)
{
    BIO *bio;
    X509 *certificate;
    unsigned int expected = 0U;
    unsigned int parsed = 0U;
    if (!strict_pem_count(bundle, bundle_length, &expected, 1))
        return PM3000_ACME_CERTIFICATE_INVALID;
    bio = BIO_new_mem_buf((void *)bundle, (int)bundle_length);
    if (bio == (BIO *)0) return PM3000_ACME_CERTIFICATE_IO;
    while ((certificate = PEM_read_bio_X509(
                bio, (X509 **)0, (void *)0, (void *)0)) != (X509 *)0) {
        ++parsed;
        X509_free(certificate);
    }
    BIO_free(bio);
    return parsed == expected ? PM3000_ACME_CERTIFICATE_OK :
                                PM3000_ACME_CERTIFICATE_INVALID;
}

static int exact_dns_names(X509 *certificate, const char *const *dns_names,
                           unsigned int dns_name_count)
{
    OPENSSL_STACK *names;
    unsigned char matched[CERTIFICATE_NAMES_MAX];
    int count;
    int item;
    unsigned int expected;
    memset(matched, 0, sizeof(matched));
    names = (OPENSSL_STACK *)X509_get_ext_d2i(
        certificate, NID_SUBJECT_ALT_NAME, (int *)0, (int *)0);
    if (names == (OPENSSL_STACK *)0) return 0;
    count = PM3000_SK_NUM(names);
    if (count != (int)dns_name_count) {
        GENERAL_NAMES_free(names);
        return 0;
    }
    for (item = 0; item < count; ++item) {
        GENERAL_NAME *name = (GENERAL_NAME *)PM3000_SK_VALUE(names, item);
        const ASN1_STRING *value;
        unsigned char *bytes;
        char raw[PM3000_ACME_HOST_MAX + 1U];
        char normalized[PM3000_ACME_HOST_MAX + 1U];
        int type = -1;
        int length;
        value = (const ASN1_STRING *)GENERAL_NAME_get0_value(name, &type);
        if (type != GEN_DNS_VALUE || value == (const ASN1_STRING *)0 ||
            (length = ASN1_STRING_length(value)) <= 0 ||
            length > (int)PM3000_ACME_HOST_MAX) goto rejected;
        bytes = ASN1_STRING_data((ASN1_STRING *)value);
        if (bytes == (unsigned char *)0) goto rejected;
        for (expected = 0U; expected < (unsigned int)length; ++expected) {
            if (bytes[expected] == 0U || bytes[expected] > 0x7fU)
                goto rejected;
            raw[expected] = (char)bytes[expected];
        }
        raw[length] = '\0';
        if (pm3000_acme_dns_name_normalize(raw, normalized,
                                            sizeof(normalized)) !=
            PM3000_ACME_URL_OK) goto rejected;
        for (expected = 0U; expected < dns_name_count; ++expected) {
            char wanted[PM3000_ACME_HOST_MAX + 1U];
            if (pm3000_acme_dns_name_normalize(
                    dns_names[expected], wanted, sizeof(wanted)) !=
                    PM3000_ACME_URL_OK) goto rejected;
            if (!matched[expected] && strcmp(normalized, wanted) == 0) break;
        }
        if (expected == dns_name_count) goto rejected;
        matched[expected] = 1U;
    }
    GENERAL_NAMES_free(names);
    return 1;
rejected:
    GENERAL_NAMES_free(names);
    return 0;
}

int pm3000_acme_certificate_validate_bytes(
    const unsigned char *certificate_chain, unsigned int certificate_length,
    const char *ca_file,
    const struct pm3000_acme_key *private_key,
    const char *const *dns_names, unsigned int dns_name_count)
{
    BIO *bio = (BIO *)0;
    X509 *leaf = (X509 *)0;
    X509 *certificate;
    X509_STORE *store = (X509_STORE *)0;
    X509_STORE_CTX *store_context = (X509_STORE_CTX *)0;
    OPENSSL_STACK *untrusted = (OPENSSL_STACK *)0;
    unsigned int chain_count = 0U;
    unsigned int expected_count = 0U;
    int result = PM3000_ACME_CERTIFICATE_INVALID;
    if (certificate_chain == (const unsigned char *)0 ||
        ca_file == (const char *)0 ||
        private_key == (const struct pm3000_acme_key *)0 ||
        private_key->handle == (void *)0 ||
        dns_names == (const char *const *)0 || dns_name_count == 0U ||
        dns_name_count > CERTIFICATE_NAMES_MAX ||
        !strict_pem_count(certificate_chain, certificate_length,
                          &expected_count, 0))
        return PM3000_ACME_CERTIFICATE_INVALID;
    bio = BIO_new_mem_buf((void *)certificate_chain, (int)certificate_length);
    if (bio == (BIO *)0) return PM3000_ACME_CERTIFICATE_IO;
    leaf = PEM_read_bio_X509(bio, (X509 **)0, (void *)0, (void *)0);
    if (leaf == (X509 *)0) goto done;
    untrusted = PM3000_SK_NEW_NULL();
    if (untrusted == (OPENSSL_STACK *)0) goto done;
    while ((certificate = PEM_read_bio_X509(
                bio, (X509 **)0, (void *)0, (void *)0)) != (X509 *)0) {
        if (++chain_count > CERTIFICATE_CHAIN_MAX ||
            !PM3000_SK_PUSH(untrusted, certificate)) {
            X509_free(certificate);
            goto done;
        }
    }
    if (chain_count + 1U != expected_count) goto done;
    store = X509_STORE_new();
    store_context = X509_STORE_CTX_new();
    if (store == (X509_STORE *)0 ||
        store_context == (X509_STORE_CTX *)0 ||
        !X509_STORE_load_locations(store, ca_file, (const char *)0) ||
        !X509_STORE_CTX_init(store_context, store, leaf, untrusted) ||
        X509_verify_cert(store_context) != 1) {
        result = PM3000_ACME_CERTIFICATE_TRUST;
        goto done;
    }
    if (X509_check_private_key(
            leaf, (EVP_PKEY *)private_key->handle) != 1) {
        result = PM3000_ACME_CERTIFICATE_KEY;
        goto done;
    }
    if (!exact_dns_names(leaf, dns_names, dns_name_count)) {
        result = PM3000_ACME_CERTIFICATE_NAME;
        goto done;
    }
    result = PM3000_ACME_CERTIFICATE_OK;
done:
    if (store_context != (X509_STORE_CTX *)0)
        X509_STORE_CTX_free(store_context);
    if (store != (X509_STORE *)0) X509_STORE_free(store);
    if (untrusted != (OPENSSL_STACK *)0)
        PM3000_SK_POP_FREE(untrusted, X509_free);
    if (leaf != (X509 *)0) X509_free(leaf);
    if (bio != (BIO *)0) BIO_free(bio);
    return result;
}

int pm3000_acme_certificate_validate(
    const char *certificate_chain_path, const char *ca_file,
    const struct pm3000_acme_key *private_key,
    const char *const *dns_names, unsigned int dns_name_count)
{
    FILE *file;
    size_t length;
    int read_failed;
    int close_failed;
    if (certificate_chain_path == (const char *)0)
        return PM3000_ACME_CERTIFICATE_INVALID;
    file = fopen(certificate_chain_path, "rb");
    if (file == (FILE *)0) return PM3000_ACME_CERTIFICATE_IO;
    length = fread(certificate_file, 1U, CERTIFICATE_FILE_MAX + 1U, file);
    read_failed = ferror(file) || !feof(file);
    close_failed = fclose(file) != 0;
    if (read_failed || close_failed || length == 0U ||
        length > CERTIFICATE_FILE_MAX)
        return PM3000_ACME_CERTIFICATE_INVALID;
    return pm3000_acme_certificate_validate_bytes(
        certificate_file, (unsigned int)length, ca_file, private_key,
        dns_names, dns_name_count);
}
