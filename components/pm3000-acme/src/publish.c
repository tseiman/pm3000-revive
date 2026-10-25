#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_publish.h"
#include "pm3000_acme_certificate.h"
#include "pm3000_acme_store.h"

#include <stdio.h>
#include <unistd.h>

#define PUBLISH_PATH_MAX 1024U

int pm3000_acme_publish_certificate(
    const char *state_root, const unsigned char *certificate_pem,
    unsigned int certificate_length, const char *ca_file,
    const struct pm3000_acme_key *certificate_key,
    const char *const *dns_names, unsigned int dns_name_count)
{
    char candidate_path[PUBLISH_PATH_MAX + 1U];
    int amount;
    int store_result;
    int result = PM3000_ACME_PUBLISH_REJECTED;
    if (state_root == (const char *)0 ||
        certificate_pem == (const unsigned char *)0 ||
        certificate_length == 0U || ca_file == (const char *)0 ||
        certificate_key == (const struct pm3000_acme_key *)0 ||
        dns_names == (const char *const *)0 || dns_name_count == 0U)
        return PM3000_ACME_PUBLISH_INVALID;
    amount = snprintf(candidate_path, sizeof(candidate_path),
                      "%s/certificate.candidate", state_root);
    if (amount <= 0 || (unsigned int)amount >= sizeof(candidate_path))
        return PM3000_ACME_PUBLISH_INVALID;
    store_result = pm3000_acme_store_write(
        state_root, "certificate.candidate", certificate_pem,
        certificate_length, 0600);
    if (store_result != PM3000_ACME_STORE_OK &&
        store_result != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        return PM3000_ACME_PUBLISH_IO;
    if (pm3000_acme_certificate_validate(
            candidate_path, ca_file, certificate_key, dns_names,
            dns_name_count) != PM3000_ACME_CERTIFICATE_OK)
        goto done;
    store_result = pm3000_acme_store_write(
        state_root, "certificate.pem", certificate_pem,
        certificate_length, 0644);
    if (store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        result = PM3000_ACME_PUBLISH_COMMITTED_UNCERTAIN;
    else if (store_result == PM3000_ACME_STORE_OK)
        result = PM3000_ACME_PUBLISH_OK;
    else
        result = PM3000_ACME_PUBLISH_IO;
done:
    (void)unlink(candidate_path);
    return result;
}
