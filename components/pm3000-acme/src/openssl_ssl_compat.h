#ifndef PM3000_ACME_OPENSSL_SSL_COMPAT_H
#define PM3000_ACME_OPENSSL_SSL_COMPAT_H

#include "openssl_compat.h"

typedef struct ssl_method_st SSL_METHOD;
typedef struct ssl_ctx_st SSL_CTX;
typedef struct ssl_st SSL;
#ifndef PM3000_X509_TYPE_DEFINED
#define PM3000_X509_TYPE_DEFINED
struct x509_st;
typedef struct x509_st X509;
#endif
typedef struct asn1_string_st ASN1_STRING;
typedef struct GENERAL_NAME_st GENERAL_NAME;

#ifdef PM3000_OPENSSL3_HOST
int OPENSSL_init_ssl(unsigned long options, const void *settings);
#define PM3000_SSL_GLOBAL_INIT() OPENSSL_init_ssl(0UL, (const void *)0)
#else
int SSL_library_init(void);
void SSL_load_error_strings(void);
#define PM3000_SSL_GLOBAL_INIT() (SSL_load_error_strings(), SSL_library_init())
#endif

const SSL_METHOD *TLSv1_2_client_method(void);
SSL_CTX *SSL_CTX_new(const SSL_METHOD *method);
void SSL_CTX_free(SSL_CTX *context);
int SSL_CTX_load_verify_locations(SSL_CTX *context, const char *ca_file,
                                  const char *ca_path);
void SSL_CTX_set_verify(SSL_CTX *context, int mode,
                        int (*callback)(int, void *));
SSL *SSL_new(SSL_CTX *context);
void SSL_free(SSL *session);
int SSL_set_fd(SSL *session, int descriptor);
long SSL_ctrl(SSL *session, int command, long argument, void *pointer);
int SSL_connect(SSL *session);
long SSL_get_verify_result(const SSL *session);
#ifdef PM3000_OPENSSL3_HOST
X509 *SSL_get1_peer_certificate(const SSL *session);
#define PM3000_SSL_GET_PEER_CERTIFICATE(session) \
    SSL_get1_peer_certificate(session)
#else
X509 *SSL_get_peer_certificate(const SSL *session);
#define PM3000_SSL_GET_PEER_CERTIFICATE(session) \
    SSL_get_peer_certificate(session)
#endif
int SSL_read(SSL *session, void *buffer, int amount);
int SSL_write(SSL *session, const void *buffer, int amount);
int SSL_shutdown(SSL *session);

void *X509_get_ext_d2i(const X509 *certificate, int nid, int *critical,
                       int *index);
void X509_free(X509 *certificate);
void GENERAL_NAMES_free(OPENSSL_STACK *names);
const void *GENERAL_NAME_get0_value(const GENERAL_NAME *name, int *type);
int ASN1_STRING_length(const ASN1_STRING *string);
unsigned char *ASN1_STRING_data(ASN1_STRING *string);
#ifdef PM3000_OPENSSL3_HOST
int OPENSSL_sk_num(const OPENSSL_STACK *stack);
void *OPENSSL_sk_value(const OPENSSL_STACK *stack, int index);
#define PM3000_SK_NUM(stack) OPENSSL_sk_num(stack)
#define PM3000_SK_VALUE(stack, index) OPENSSL_sk_value((stack), (index))
#else
int sk_num(const OPENSSL_STACK *stack);
void *sk_value(const OPENSSL_STACK *stack, int index);
#define PM3000_SK_NUM(stack) sk_num(stack)
#define PM3000_SK_VALUE(stack, index) sk_value((stack), (index))
#endif
X509 *PEM_read_bio_X509(BIO *bio, X509 **certificate,
                        void *callback, void *argument);

#endif
