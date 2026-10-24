#include "pm3000_acme_certificate.h"
#include "pm3000_acme_tls.h"
#include "openssl_compat.h"

#define CERTIFICATE_NAMES_MAX 16U
#define CERTIFICATE_CHAIN_MAX 8U

int pm3000_acme_certificate_validate(
    const char *certificate_chain_path, const char *ca_file,
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
    unsigned int index;
    int result = PM3000_ACME_CERTIFICATE_INVALID;
    if (certificate_chain_path == (const char *)0 ||
        ca_file == (const char *)0 ||
        private_key == (const struct pm3000_acme_key *)0 ||
        private_key->handle == (void *)0 ||
        dns_names == (const char *const *)0 || dns_name_count == 0U ||
        dns_name_count > CERTIFICATE_NAMES_MAX)
        return PM3000_ACME_CERTIFICATE_INVALID;
    bio = BIO_new_file(certificate_chain_path, "r");
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
    for (index = 0U; index < dns_name_count; ++index) {
        if (pm3000_acme_tls_certificate_file_matches(
                certificate_chain_path, dns_names[index]) !=
            PM3000_ACME_TLS_OK) {
            result = PM3000_ACME_CERTIFICATE_NAME;
            goto done;
        }
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
