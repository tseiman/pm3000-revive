#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_client.h"
#include "pm3000_acme_transport.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int no_sleep(void *context, unsigned int seconds)
{
    (void)context;
    return seconds == 0U ? -1 : 0;
}

int main(int argc, char **argv)
{
    static const char *names[] = {"pdu1.tsei.mdn"};
    struct pm3000_acme_key account_key = {0};
    struct pm3000_acme_key certificate_key = {0};
    struct pm3000_acme_client_config config;
    struct pm3000_acme_client_io io;
    static struct pm3000_acme_client_workspace client_workspace;
    static struct pm3000_acme_transport_workspace transport_workspace;
    static struct pm3000_acme_client_result result;
    struct pm3000_acme_transport transport;
    char directory[256];
    char challenge_path[512];
    int status;
    if (argc != 3) return 2;
    snprintf(directory, sizeof(directory), "https://localhost:%s/directory",
             argv[1]);
    snprintf(challenge_path, sizeof(challenge_path), "%s/dG9rZW4", argv[2]);
    unlink(challenge_path);
    if (pm3000_acme_crypto_key_load(
            "tests/fixtures/account-test-key.pem", &account_key) !=
            PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_load(
            "tests/fixtures/account-test-key.pem", &certificate_key) !=
            PM3000_ACME_CRYPTO_OK) return 2;
    memset(&transport, 0, sizeof(transport));
    transport.ca_file = "tests/fixtures/tls/ca.pem";
    transport.timeout_seconds = 5U;
    transport.workspace = &transport_workspace;
    memset(&config, 0, sizeof(config));
    config.directory_url = directory;
    config.challenge_webroot = argv[2];
    config.dns_names = names;
    config.dns_name_count = 1U;
    config.poll_attempts = 5U;
    config.account_key = &account_key;
    config.certificate_key = &certificate_key;
    io.exchange = pm3000_acme_transport_exchange;
    io.sleep = no_sleep;
    io.context = &transport;
    status = pm3000_acme_client_issue(
        &config, &io, &client_workspace, &result);
    pm3000_acme_crypto_key_free(&certificate_key);
    pm3000_acme_crypto_key_free(&account_key);
    if (status != PM3000_ACME_CLIENT_OK ||
        strstr((const char *)result.certificate_pem,
               "BEGIN CERTIFICATE") == NULL ||
        lstat(challenge_path, &(struct stat){0}) == 0) {
        fprintf(stderr, "network.client.status=%d phase=%s reason=%s\n",
                status,
                pm3000_acme_failure_phase_name(result.failure_phase),
                pm3000_acme_failure_reason_name(result.failure_reason));
        return 1;
    }
    puts("network.client.complete=yes");
    return 0;
}
