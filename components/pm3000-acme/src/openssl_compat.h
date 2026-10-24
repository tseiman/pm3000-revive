#ifndef PM3000_ACME_OPENSSL_COMPAT_H
#define PM3000_ACME_OPENSSL_COMPAT_H

typedef struct bio_st BIO;
typedef struct evp_pkey_st EVP_PKEY;
typedef struct evp_md_st EVP_MD;
typedef struct env_md_ctx_st EVP_MD_CTX;
typedef struct rsa_st RSA;
typedef struct bignum_st BIGNUM;
typedef struct X509_req_st X509_REQ;
typedef struct X509_name_st X509_NAME;
typedef struct X509_extension_st X509_EXTENSION;
#ifndef PM3000_X509_TYPE_DEFINED
#define PM3000_X509_TYPE_DEFINED
struct x509_st;
typedef struct x509_st X509;
#endif
typedef struct x509_store_st X509_STORE;
typedef struct x509_store_ctx_st X509_STORE_CTX;
typedef struct stack_st OPENSSL_STACK;

BIO *BIO_new_file(const char *filename, const char *mode);
int BIO_free(BIO *bio);
EVP_PKEY *PEM_read_bio_PrivateKey(BIO *bio, EVP_PKEY **key,
                                  void *callback, void *argument);
int PEM_write_bio_PrivateKey(BIO *bio, EVP_PKEY *key, const void *cipher,
                             unsigned char *password, int password_length,
                             void *callback, void *argument);
X509 *PEM_read_bio_X509(BIO *bio, X509 **certificate,
                        void *callback, void *argument);
void X509_free(X509 *certificate);
X509_STORE *X509_STORE_new(void);
void X509_STORE_free(X509_STORE *store);
int X509_STORE_load_locations(X509_STORE *store, const char *file,
                              const char *directory);
X509_STORE_CTX *X509_STORE_CTX_new(void);
void X509_STORE_CTX_free(X509_STORE_CTX *context);
int X509_STORE_CTX_init(X509_STORE_CTX *context, X509_STORE *store,
                        X509 *certificate, void *untrusted);
int X509_verify_cert(X509_STORE_CTX *context);
int X509_check_private_key(X509 *certificate, EVP_PKEY *key);

EVP_PKEY *EVP_PKEY_new(void);
void EVP_PKEY_free(EVP_PKEY *key);
int EVP_PKEY_assign(EVP_PKEY *key, int type, void *material);
#ifdef PM3000_OPENSSL3_HOST
int EVP_PKEY_get_size(const EVP_PKEY *key);
#define PM3000_EVP_PKEY_SIZE(key) EVP_PKEY_get_size(key)
#else
int EVP_PKEY_size(EVP_PKEY *key);
#define PM3000_EVP_PKEY_SIZE(key) EVP_PKEY_size(key)
#endif
int i2d_PublicKey(EVP_PKEY *key, unsigned char **output);

RSA *RSA_new(void);
void RSA_free(RSA *rsa);
int RSA_generate_key_ex(RSA *rsa, int bits, BIGNUM *exponent,
                        void *callback);
BIGNUM *BN_new(void);
void BN_free(BIGNUM *number);
int BN_set_word(BIGNUM *number, unsigned long value);

#ifdef PM3000_OPENSSL3_HOST
EVP_MD_CTX *EVP_MD_CTX_new(void);
void EVP_MD_CTX_free(EVP_MD_CTX *context);
#define PM3000_EVP_MD_CTX_CREATE() EVP_MD_CTX_new()
#define PM3000_EVP_MD_CTX_DESTROY(context) EVP_MD_CTX_free(context)
#else
EVP_MD_CTX *EVP_MD_CTX_create(void);
void EVP_MD_CTX_destroy(EVP_MD_CTX *context);
#define PM3000_EVP_MD_CTX_CREATE() EVP_MD_CTX_create()
#define PM3000_EVP_MD_CTX_DESTROY(context) EVP_MD_CTX_destroy(context)
#endif
const EVP_MD *EVP_sha256(void);
int EVP_DigestInit_ex(EVP_MD_CTX *context, const EVP_MD *type, void *engine);
int EVP_DigestUpdate(EVP_MD_CTX *context, const void *data,
                     unsigned long length);
int EVP_SignFinal(EVP_MD_CTX *context, unsigned char *signature,
                  unsigned int *signature_length, EVP_PKEY *key);
int EVP_VerifyFinal(EVP_MD_CTX *context, const unsigned char *signature,
                    unsigned int signature_length, EVP_PKEY *key);
unsigned char *SHA256(const unsigned char *data, unsigned long length,
                      unsigned char *digest);

X509_REQ *X509_REQ_new(void);
void X509_REQ_free(X509_REQ *request);
int X509_REQ_set_version(X509_REQ *request, long version);
int X509_REQ_set_subject_name(X509_REQ *request, X509_NAME *name);
int X509_REQ_set_pubkey(X509_REQ *request, EVP_PKEY *key);
int X509_REQ_add_extensions(X509_REQ *request, OPENSSL_STACK *extensions);
int X509_REQ_sign(X509_REQ *request, EVP_PKEY *key, const EVP_MD *digest);
int i2d_X509_REQ(X509_REQ *request, unsigned char **output);
X509_NAME *X509_NAME_new(void);
void X509_NAME_free(X509_NAME *name);
int X509_NAME_add_entry_by_txt(X509_NAME *name, const char *field,
                               int type, const unsigned char *bytes,
                               int length, int location, int set);
X509_EXTENSION *X509V3_EXT_conf_nid(void *configuration, void *context,
                                    int nid, char *value);
void X509_EXTENSION_free(X509_EXTENSION *extension);
#ifdef PM3000_OPENSSL3_HOST
OPENSSL_STACK *OPENSSL_sk_new_null(void);
int OPENSSL_sk_push(OPENSSL_STACK *stack, const void *value);
void OPENSSL_sk_pop_free(OPENSSL_STACK *stack, void (*free_value)(void *));
#define PM3000_SK_NEW_NULL() OPENSSL_sk_new_null()
#define PM3000_SK_PUSH(stack, value) OPENSSL_sk_push((stack), (value))
#define PM3000_SK_POP_FREE(stack, callback) \
    OPENSSL_sk_pop_free((stack), (void (*)(void *))(callback))
#else
OPENSSL_STACK *sk_new_null(void);
int sk_push(OPENSSL_STACK *stack, void *value);
void sk_pop_free(OPENSSL_STACK *stack, void (*free_value)(void *));
#define PM3000_SK_NEW_NULL() sk_new_null()
#define PM3000_SK_PUSH(stack, value) sk_push((stack), (value))
#define PM3000_SK_POP_FREE(stack, callback) \
    sk_pop_free((stack), (void (*)(void *))(callback))
#endif

#endif
