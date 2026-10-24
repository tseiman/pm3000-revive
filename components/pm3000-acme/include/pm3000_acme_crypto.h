#ifndef PM3000_ACME_CRYPTO_H
#define PM3000_ACME_CRYPTO_H

#define PM3000_ACME_RSA_SIGNATURE_MAX 512U
#define PM3000_ACME_JWK_MAX 800U
#define PM3000_ACME_THUMBPRINT_MAX 64U
#define PM3000_ACME_CSR_DER_MAX 4096U
#define PM3000_ACME_CSR_NAMES_MAX 16U

enum pm3000_acme_crypto_result {
    PM3000_ACME_CRYPTO_OK = 0,
    PM3000_ACME_CRYPTO_INVALID = -1,
    PM3000_ACME_CRYPTO_LIMIT = -2,
    PM3000_ACME_CRYPTO_IO = -3,
    PM3000_ACME_CRYPTO_OPENSSL = -4
};

struct pm3000_acme_key {
    void *handle;
};

int pm3000_acme_crypto_key_load(const char *path,
                                struct pm3000_acme_key *key);
int pm3000_acme_crypto_key_generate_rsa2048(struct pm3000_acme_key *key);
int pm3000_acme_crypto_key_write(const char *path,
                                 const struct pm3000_acme_key *key);
void pm3000_acme_crypto_key_free(struct pm3000_acme_key *key);
int pm3000_acme_crypto_account_jwk(const struct pm3000_acme_key *key,
                                  char *output, unsigned int capacity);
int pm3000_acme_crypto_thumbprint(const struct pm3000_acme_key *key,
                                 char *output, unsigned int capacity);
int pm3000_acme_crypto_sign_rs256(const struct pm3000_acme_key *key,
                                 const unsigned char *message,
                                 unsigned int message_length,
                                 unsigned char *signature,
                                 unsigned int signature_capacity,
                                 unsigned int *signature_length);
int pm3000_acme_crypto_verify_rs256(const struct pm3000_acme_key *key,
                                   const unsigned char *message,
                                   unsigned int message_length,
                                   const unsigned char *signature,
                                   unsigned int signature_length);
int pm3000_acme_crypto_csr_der(const struct pm3000_acme_key *key,
                              const char *const *dns_names,
                              unsigned int dns_name_count,
                              unsigned char *output,
                              unsigned int output_capacity,
                              unsigned int *output_length);

#endif
