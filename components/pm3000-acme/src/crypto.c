#include "pm3000_acme_crypto.h"
#include "pm3000_acme_base64url.h"
#include "pm3000_acme_url.h"
#include "openssl_compat.h"

#define EVP_PKEY_RSA_TYPE 6
#define RSA_PUBLIC_EXPONENT 65537UL
#define PUBLIC_DER_MAX 1024U

static EVP_PKEY *key_handle(const struct pm3000_acme_key *key)
{
    if (key == (const struct pm3000_acme_key *)0) return (EVP_PKEY *)0;
    return (EVP_PKEY *)key->handle;
}

void pm3000_acme_crypto_key_free(struct pm3000_acme_key *key)
{
    if (key == (struct pm3000_acme_key *)0) return;
    if (key->handle != (void *)0) EVP_PKEY_free((EVP_PKEY *)key->handle);
    key->handle = (void *)0;
}

int pm3000_acme_crypto_key_load(const char *path,
                                struct pm3000_acme_key *key)
{
    BIO *bio;
    EVP_PKEY *loaded;
    if (path == (const char *)0 || key == (struct pm3000_acme_key *)0 ||
        key->handle != (void *)0) return PM3000_ACME_CRYPTO_INVALID;
    bio = BIO_new_file(path, "r");
    if (bio == (BIO *)0) return PM3000_ACME_CRYPTO_IO;
    loaded = PEM_read_bio_PrivateKey(bio, (EVP_PKEY **)0, (void *)0,
                                     (void *)0);
    BIO_free(bio);
    if (loaded == (EVP_PKEY *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    key->handle = loaded;
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_key_load_pem(const unsigned char *pem,
                                    unsigned int pem_length,
                                    struct pm3000_acme_key *key)
{
    BIO *bio;
    EVP_PKEY *loaded;
    if (pem == (const unsigned char *)0 || pem_length == 0U ||
        pem_length > 4096U || key == (struct pm3000_acme_key *)0 ||
        key->handle != (void *)0) return PM3000_ACME_CRYPTO_INVALID;
    bio = BIO_new_mem_buf(pem, (int)pem_length);
    if (bio == (BIO *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    loaded = PEM_read_bio_PrivateKey(bio, (EVP_PKEY **)0, (void *)0,
                                     (void *)0);
    BIO_free(bio);
    if (loaded == (EVP_PKEY *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    key->handle = loaded;
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_key_generate_rsa2048(struct pm3000_acme_key *key)
{
    EVP_PKEY *container = (EVP_PKEY *)0;
    RSA *rsa = (RSA *)0;
    BIGNUM *exponent = (BIGNUM *)0;
    if (key == (struct pm3000_acme_key *)0 || key->handle != (void *)0)
        return PM3000_ACME_CRYPTO_INVALID;
    container = EVP_PKEY_new();
    rsa = RSA_new();
    exponent = BN_new();
    if (container == (EVP_PKEY *)0 || rsa == (RSA *)0 ||
        exponent == (BIGNUM *)0 || !BN_set_word(exponent, RSA_PUBLIC_EXPONENT) ||
        !RSA_generate_key_ex(rsa, 2048, exponent, (void *)0) ||
        !EVP_PKEY_assign(container, EVP_PKEY_RSA_TYPE, rsa)) {
        if (exponent != (BIGNUM *)0) BN_free(exponent);
        if (rsa != (RSA *)0) RSA_free(rsa);
        if (container != (EVP_PKEY *)0) EVP_PKEY_free(container);
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    BN_free(exponent);
    key->handle = container;
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_key_pem(const struct pm3000_acme_key *key,
                               unsigned char *output,
                               unsigned int output_capacity,
                               unsigned int *output_length)
{
    BIO *bio;
    long pending;
    int read_length;
    EVP_PKEY *handle = key_handle(key);
    if (handle == (EVP_PKEY *)0 || output == (unsigned char *)0 ||
        output_length == (unsigned int *)0 || output_capacity < 2U)
        return PM3000_ACME_CRYPTO_INVALID;
    *output_length = 0U;
    bio = BIO_new(BIO_s_mem());
    if (bio == (BIO *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    if (!PEM_write_bio_PrivateKey(bio, handle, (const void *)0,
                                  (unsigned char *)0, 0, (void *)0,
                                  (void *)0)) {
        BIO_free(bio);
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    pending = BIO_ctrl(bio, 10, 0L, (void *)0);
    if (pending <= 0L || (unsigned long)pending >= output_capacity ||
        pending > 2147483647L) {
        BIO_free(bio);
        return PM3000_ACME_CRYPTO_LIMIT;
    }
    read_length = BIO_read(bio, output, (int)pending);
    if (!BIO_free(bio) || read_length != (int)pending)
        return PM3000_ACME_CRYPTO_OPENSSL;
    output[read_length] = '\0';
    *output_length = (unsigned int)read_length;
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_key_write(const char *path,
                                 const struct pm3000_acme_key *key)
{
    BIO *bio;
    int result;
    EVP_PKEY *handle = key_handle(key);
    if (path == (const char *)0 || handle == (EVP_PKEY *)0)
        return PM3000_ACME_CRYPTO_INVALID;
    bio = BIO_new_file(path, "w");
    if (bio == (BIO *)0) return PM3000_ACME_CRYPTO_IO;
    result = PEM_write_bio_PrivateKey(bio, handle, (const void *)0,
                                      (unsigned char *)0, 0, (void *)0,
                                      (void *)0);
    if (!BIO_free(bio) || !result) return PM3000_ACME_CRYPTO_OPENSSL;
    return PM3000_ACME_CRYPTO_OK;
}

static int der_length(const unsigned char *data, unsigned int total,
                      unsigned int *offset, unsigned int *length)
{
    unsigned int first;
    unsigned int amount;
    unsigned int value = 0U;
    unsigned int index;
    if (*offset >= total) return 0;
    first = data[(*offset)++];
    if ((first & 0x80U) == 0U) {
        *length = first;
        return *offset + *length <= total;
    }
    amount = first & 0x7fU;
    if (amount == 0U || amount > 4U || *offset + amount > total ||
        data[*offset] == 0U) return 0;
    for (index = 0U; index < amount; ++index) {
        if (value > 0x00ffffffU) return 0;
        value = (value << 8) | data[(*offset)++];
    }
    if (value < 128U || *offset + value > total) return 0;
    *length = value;
    return 1;
}

static int der_tlv(const unsigned char *data, unsigned int total,
                   unsigned int *offset, unsigned int tag,
                   const unsigned char **value, unsigned int *value_length)
{
    if (*offset >= total || data[(*offset)++] != (unsigned char)tag ||
        !der_length(data, total, offset, value_length)) return 0;
    *value = data + *offset;
    *offset += *value_length;
    return 1;
}

static int rsa_components(EVP_PKEY *key, unsigned char der[PUBLIC_DER_MAX],
                          const unsigned char **modulus,
                          unsigned int *modulus_length,
                          const unsigned char **exponent,
                          unsigned int *exponent_length)
{
    unsigned char *cursor = der;
    const unsigned char *sequence;
    unsigned int sequence_length;
    unsigned int offset = 0U;
    unsigned int inner = 0U;
    int length = i2d_PublicKey(key, (unsigned char **)0);
    if (length <= 0 || (unsigned int)length > PUBLIC_DER_MAX ||
        i2d_PublicKey(key, &cursor) != length ||
        !der_tlv(der, (unsigned int)length, &offset, 0x30U, &sequence,
                 &sequence_length) || offset != (unsigned int)length ||
        !der_tlv(sequence, sequence_length, &inner, 0x02U, modulus,
                 modulus_length) ||
        !der_tlv(sequence, sequence_length, &inner, 0x02U, exponent,
                 exponent_length) || inner != sequence_length ||
        *modulus_length == 0U || *exponent_length == 0U) {
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    if ((*modulus)[0] == 0U) {
        ++*modulus;
        --*modulus_length;
    }
    if ((*exponent)[0] == 0U) {
        ++*exponent;
        --*exponent_length;
    }
    if (*modulus_length == 0U || *exponent_length == 0U) {
        return PM3000_ACME_CRYPTO_INVALID;
    }
    return PM3000_ACME_CRYPTO_OK;
}

static int append_text(char *output, unsigned int capacity, unsigned int *used,
                       const char *text)
{
    unsigned int index = 0U;
    while (text[index] != '\0') {
        if (*used + 1U >= capacity) return PM3000_ACME_CRYPTO_LIMIT;
        output[(*used)++] = text[index++];
    }
    output[*used] = '\0';
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_account_jwk(const struct pm3000_acme_key *key,
                                  char *output, unsigned int capacity)
{
    unsigned char der[PUBLIC_DER_MAX];
    const unsigned char *modulus;
    const unsigned char *exponent;
    unsigned int modulus_length;
    unsigned int exponent_length;
    char modulus_text[700];
    char exponent_text[32];
    unsigned int used = 0U;
    int result;
    EVP_PKEY *handle = key_handle(key);
    if (output == (char *)0 || capacity == 0U || handle == (EVP_PKEY *)0)
        return PM3000_ACME_CRYPTO_INVALID;
    output[0] = '\0';
    result = rsa_components(handle, der, &modulus, &modulus_length, &exponent,
                            &exponent_length);
    if (result != PM3000_ACME_CRYPTO_OK) return result;
    if (pm3000_acme_base64url_encode(modulus, modulus_length, modulus_text,
                                     sizeof(modulus_text)) !=
            PM3000_ACME_BASE64URL_OK ||
        pm3000_acme_base64url_encode(exponent, exponent_length, exponent_text,
                                     sizeof(exponent_text)) !=
            PM3000_ACME_BASE64URL_OK ||
        append_text(output, capacity, &used, "{\"e\":\"") != 0 ||
        append_text(output, capacity, &used, exponent_text) != 0 ||
        append_text(output, capacity, &used, "\",\"kty\":\"RSA\",\"n\":\"") != 0 ||
        append_text(output, capacity, &used, modulus_text) != 0 ||
        append_text(output, capacity, &used, "\"}") != 0) {
        output[0] = '\0';
        return PM3000_ACME_CRYPTO_LIMIT;
    }
    return PM3000_ACME_CRYPTO_OK;
}

static unsigned int text_length(const char *text)
{
    unsigned int length = 0U;
    while (text[length] != '\0') ++length;
    return length;
}

int pm3000_acme_crypto_thumbprint(const struct pm3000_acme_key *key,
                                 char *output, unsigned int capacity)
{
    char jwk[PM3000_ACME_JWK_MAX];
    unsigned char digest[32];
    if (output == (char *)0 || capacity == 0U) return PM3000_ACME_CRYPTO_INVALID;
    output[0] = '\0';
    if (pm3000_acme_crypto_account_jwk(key, jwk, sizeof(jwk)) !=
            PM3000_ACME_CRYPTO_OK ||
        SHA256((const unsigned char *)jwk, (unsigned long)text_length(jwk),
               digest) == (unsigned char *)0 ||
        pm3000_acme_base64url_encode(digest, sizeof(digest), output, capacity) !=
            PM3000_ACME_BASE64URL_OK) {
        output[0] = '\0';
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_sign_rs256(const struct pm3000_acme_key *key,
                                 const unsigned char *message,
                                 unsigned int message_length,
                                 unsigned char *signature,
                                 unsigned int signature_capacity,
                                 unsigned int *signature_length)
{
    EVP_PKEY *handle = key_handle(key);
    EVP_MD_CTX *context;
    int required;
    if (handle == (EVP_PKEY *)0 || message == (const unsigned char *)0 ||
        signature == (unsigned char *)0 ||
        signature_length == (unsigned int *)0) return PM3000_ACME_CRYPTO_INVALID;
    *signature_length = 0U;
    required = PM3000_EVP_PKEY_SIZE(handle);
    if (required <= 0 || (unsigned int)required > signature_capacity ||
        (unsigned int)required > PM3000_ACME_RSA_SIGNATURE_MAX)
        return PM3000_ACME_CRYPTO_LIMIT;
    context = PM3000_EVP_MD_CTX_CREATE();
    if (context == (EVP_MD_CTX *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    if (!EVP_DigestInit_ex(context, EVP_sha256(), (void *)0) ||
        !EVP_DigestUpdate(context, message, (unsigned long)message_length) ||
        !EVP_SignFinal(context, signature, signature_length, handle)) {
        PM3000_EVP_MD_CTX_DESTROY(context);
        *signature_length = 0U;
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    PM3000_EVP_MD_CTX_DESTROY(context);
    if (*signature_length != (unsigned int)required) {
        *signature_length = 0U;
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    return PM3000_ACME_CRYPTO_OK;
}

int pm3000_acme_crypto_verify_rs256(const struct pm3000_acme_key *key,
                                   const unsigned char *message,
                                   unsigned int message_length,
                                   const unsigned char *signature,
                                   unsigned int signature_length)
{
    EVP_PKEY *handle = key_handle(key);
    EVP_MD_CTX *context;
    int result;
    if (handle == (EVP_PKEY *)0 || message == (const unsigned char *)0 ||
        signature == (const unsigned char *)0 || signature_length == 0U ||
        signature_length > PM3000_ACME_RSA_SIGNATURE_MAX)
        return PM3000_ACME_CRYPTO_INVALID;
    context = PM3000_EVP_MD_CTX_CREATE();
    if (context == (EVP_MD_CTX *)0) return PM3000_ACME_CRYPTO_OPENSSL;
    if (!EVP_DigestInit_ex(context, EVP_sha256(), (void *)0) ||
        !EVP_DigestUpdate(context, message, (unsigned long)message_length)) {
        PM3000_EVP_MD_CTX_DESTROY(context);
        return PM3000_ACME_CRYPTO_OPENSSL;
    }
    result = EVP_VerifyFinal(context, signature, signature_length, handle);
    PM3000_EVP_MD_CTX_DESTROY(context);
    return result == 1 ? PM3000_ACME_CRYPTO_OK : PM3000_ACME_CRYPTO_INVALID;
}

static int same_text(const char *left, const char *right)
{
    unsigned int index = 0U;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

int pm3000_acme_crypto_csr_der(const struct pm3000_acme_key *key,
                              const char *const *dns_names,
                              unsigned int dns_name_count,
                              unsigned char *output,
                              unsigned int output_capacity,
                              unsigned int *output_length)
{
    char normalized[PM3000_ACME_CSR_NAMES_MAX]
                   [PM3000_ACME_HOST_MAX + 1U];
    char san_value[PM3000_ACME_CSR_NAMES_MAX *
                   (PM3000_ACME_HOST_MAX + 5U)];
    unsigned int san_used = 0U;
    unsigned int index;
    unsigned int previous;
    EVP_PKEY *handle = key_handle(key);
    X509_REQ *request = (X509_REQ *)0;
    X509_NAME *subject = (X509_NAME *)0;
    X509_EXTENSION *extension = (X509_EXTENSION *)0;
    OPENSSL_STACK *extensions = (OPENSSL_STACK *)0;
    int extension_in_stack = 0;
    int encoded_length;
    unsigned char *cursor;
    int result = PM3000_ACME_CRYPTO_OPENSSL;

    if (output_length != (unsigned int *)0) *output_length = 0U;
    if (handle == (EVP_PKEY *)0 || dns_names == (const char *const *)0 ||
        output == (unsigned char *)0 || output_length == (unsigned int *)0 ||
        dns_name_count == 0U || dns_name_count > PM3000_ACME_CSR_NAMES_MAX ||
        output_capacity == 0U || output_capacity > PM3000_ACME_CSR_DER_MAX) {
        return PM3000_ACME_CRYPTO_INVALID;
    }
    san_value[0] = '\0';
    for (index = 0U; index < dns_name_count; ++index) {
        if (pm3000_acme_dns_name_normalize(
                dns_names[index], normalized[index],
                sizeof(normalized[index])) != PM3000_ACME_URL_OK) {
            return PM3000_ACME_CRYPTO_INVALID;
        }
        for (previous = 0U; previous < index; ++previous) {
            if (same_text(normalized[previous], normalized[index]))
                return PM3000_ACME_CRYPTO_INVALID;
        }
        if (index != 0U &&
            append_text(san_value, sizeof(san_value), &san_used, ",") !=
                PM3000_ACME_CRYPTO_OK) return PM3000_ACME_CRYPTO_LIMIT;
        if (append_text(san_value, sizeof(san_value), &san_used, "DNS:") !=
                PM3000_ACME_CRYPTO_OK ||
            append_text(san_value, sizeof(san_value), &san_used,
                        normalized[index]) != PM3000_ACME_CRYPTO_OK) {
            return PM3000_ACME_CRYPTO_LIMIT;
        }
    }

    request = X509_REQ_new();
    subject = X509_NAME_new();
    extensions = PM3000_SK_NEW_NULL();
    if (request == (X509_REQ *)0 || subject == (X509_NAME *)0 ||
        extensions == (OPENSSL_STACK *)0 ||
        !X509_REQ_set_version(request, 0L) ||
        !X509_NAME_add_entry_by_txt(
            subject, "CN", 0x1001, (const unsigned char *)normalized[0],
            -1, -1, 0) ||
        !X509_REQ_set_subject_name(request, subject) ||
        !X509_REQ_set_pubkey(request, handle)) goto cleanup;
    extension = X509V3_EXT_conf_nid((void *)0, (void *)0, 85, san_value);
    if (extension == (X509_EXTENSION *)0 ||
        PM3000_SK_PUSH(extensions, extension) <= 0) goto cleanup;
    extension_in_stack = 1;
    if (!X509_REQ_add_extensions(request, extensions) ||
        X509_REQ_sign(request, handle, EVP_sha256()) <= 0) goto cleanup;
    encoded_length = i2d_X509_REQ(request, (unsigned char **)0);
    if (encoded_length <= 0 || (unsigned int)encoded_length > output_capacity ||
        (unsigned int)encoded_length > PM3000_ACME_CSR_DER_MAX) {
        result = PM3000_ACME_CRYPTO_LIMIT;
        goto cleanup;
    }
    cursor = output;
    if (i2d_X509_REQ(request, &cursor) != encoded_length) goto cleanup;
    *output_length = (unsigned int)encoded_length;
    result = PM3000_ACME_CRYPTO_OK;

cleanup:
    if (extensions != (OPENSSL_STACK *)0)
        PM3000_SK_POP_FREE(extensions, X509_EXTENSION_free);
    if (extension != (X509_EXTENSION *)0 && !extension_in_stack)
        X509_EXTENSION_free(extension);
    if (subject != (X509_NAME *)0) X509_NAME_free(subject);
    if (request != (X509_REQ *)0) X509_REQ_free(request);
    if (result != PM3000_ACME_CRYPTO_OK) *output_length = 0U;
    return result;
}
