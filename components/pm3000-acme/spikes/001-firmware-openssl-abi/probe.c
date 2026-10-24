typedef unsigned int size_t;

extern int SSL_library_init(void);
extern void SSL_load_error_strings(void);
extern const char *SSLeay_version(int type);
extern long write(int descriptor, const void *buffer, size_t length);

static size_t text_length(const char *text)
{
    size_t length = 0U;
    if (text == (const char *)0) return 0U;
    while (text[length] != '\0') ++length;
    return length;
}

static int write_all(int descriptor, const char *text)
{
    size_t length = text_length(text);
    size_t used = 0U;
    while (used < length) {
        long amount = write(descriptor, text + used, length - used);
        if (amount <= 0) return -1;
        used += (size_t)amount;
    }
    return 0;
}

int main(void)
{
    const char *version;
    if (SSL_library_init() != 1) return 10;
    SSL_load_error_strings();
    version = SSLeay_version(0);
    if (version == (const char *)0) return 11;
    if (write_all(1, "openssl.version=") != 0 ||
        write_all(1, version) != 0 ||
        write_all(1, "\nacme.openssl_abi.complete=yes\n") != 0) return 12;
    return 0;
}
