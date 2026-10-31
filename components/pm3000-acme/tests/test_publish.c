#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_publish.h"
#include "pm3000_acme_store.h"

#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int read_file(const char *path, unsigned char *data,
                     unsigned int capacity, unsigned int *length)
{
    FILE *file = fopen(path, "rb");
    size_t amount;
    if (file == NULL) return -1;
    amount = fread(data, 1U, capacity, file);
    if (ferror(file) || !feof(file)) { fclose(file); return -1; }
    if (fclose(file) != 0) return -1;
    *length = (unsigned int)amount;
    return 0;
}

int main(void)
{
    char root[] = "build/publish-test-XXXXXX";
    char candidate_path[256];
    char active_path[256];
    unsigned char pem[32768U];
    unsigned char bad_pem[32768U];
    unsigned char stored[32768U];
    unsigned int pem_length = 0U;
    unsigned int stored_length = 0U;
    struct pm3000_acme_key key = {0};
    struct stat details;
    int root_fd;
    static const char *valid[] = {"acme.example.test", "localhost"};
    static const char *invalid[] = {"wrong.example.test"};
    if (mkdtemp(root) == NULL || chmod(root, 0700) != 0 ||
        snprintf(candidate_path, sizeof(candidate_path),
                 "%s/certificate.candidate", root) < 0 ||
        snprintf(active_path, sizeof(active_path),
                 "%s/certificate.pem", root) < 0 ||
        read_file("tests/fixtures/tls/issued.pem", pem, sizeof(pem),
                  &pem_length) != 0 ||
        pm3000_acme_crypto_key_load("tests/fixtures/tls/server-key.pem",
                                    &key) != PM3000_ACME_CRYPTO_OK ||
        (root_fd = open(root, O_RDONLY | O_DIRECTORY)) < 0 ||
        pm3000_acme_store_write(root, "certificate.pem",
                                (const unsigned char *)"old", 3U, 0644) !=
            PM3000_ACME_STORE_OK) return 2;
    if (pm3000_acme_publish_certificate(
            root_fd, pem, pem_length, "tests/fixtures/tls/ca.pem", &key,
            invalid, 1U) == PM3000_ACME_PUBLISH_OK ||
        pm3000_acme_store_read(root, "certificate.pem", stored,
                               sizeof(stored), &stored_length, 0) !=
            PM3000_ACME_STORE_OK || stored_length != 3U ||
        memcmp(stored, "old", 3U) != 0 ||
        lstat(candidate_path, &details) == 0) {
        fprintf(stderr, "invalid certificate replaced active state\n");
        return 1;
    }
    if (pm3000_acme_publish_certificate(
            root_fd, pem, pem_length, "tests/fixtures/tls/ca.pem", &key,
            valid, 2U) != PM3000_ACME_PUBLISH_OK ||
        pm3000_acme_store_read(root, "certificate.pem", stored,
                               sizeof(stored), &stored_length, 0) !=
            PM3000_ACME_STORE_OK || stored_length != pem_length ||
        memcmp(stored, pem, pem_length) != 0 ||
        lstat(active_path, &details) != 0 ||
        (details.st_mode & 0777) != 0600) {
        fprintf(stderr, "valid certificate publication failed\n");
        return 1;
    }
    memcpy(bad_pem, pem, pem_length);
    memcpy(bad_pem + pem_length, "\nGARBAGE\n", 9U);
    if (pm3000_acme_publish_certificate(
            root_fd, bad_pem, pem_length + 9U,
            "tests/fixtures/tls/ca.pem", &key, valid, 2U) ==
            PM3000_ACME_PUBLISH_OK ||
        pm3000_acme_store_read(root, "certificate.pem", stored,
                               sizeof(stored), &stored_length, 0) !=
            PM3000_ACME_STORE_OK || stored_length != pem_length ||
        memcmp(stored, pem, pem_length) != 0) {
        fprintf(stderr, "trailing certificate data was published\n");
        return 1;
    }
    close(root_fd);
    pm3000_acme_crypto_key_free(&key);
    puts("publish.tests.complete=yes");
    return 0;
}
