#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_app.h"
#include "pm3000_acme_client.h"
#include "pm3000_acme_config.h"
#include "pm3000_acme_json.h"
#include "pm3000_acme_publish.h"
#include "pm3000_acme_state.h"
#include "pm3000_acme_store.h"
#include "pm3000_acme_transport.h"

#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned char config_bytes[PM3000_ACME_JSON_MAX_BYTES + 1U];
static struct pm3000_acme_client_workspace client_workspace;
static struct pm3000_acme_client_result client_result;
static struct pm3000_acme_transport_workspace transport_workspace;

static int sleep_seconds(void *context, unsigned int seconds)
{
    (void)context;
    while (seconds != 0U) seconds = sleep(seconds);
    return 0;
}

static void write_status(const struct pm3000_acme_state *state,
                         const char *status)
{
    char json[96U];
    int length = snprintf(json, sizeof(json), "{\"status\":\"%s\"}\n",
                          status);
    if (length > 0 && (unsigned int)length < sizeof(json))
        (void)pm3000_acme_store_write_at(state->root_fd, "status.json",
                                         (const unsigned char *)json,
                                         (unsigned int)length, 0644);
}

static int arguments_valid(int argc, char **argv, int *debug)
{
    if (argc != 3 && argc != 4) return 0;
    if (strcmp(argv[1], "renew") != 0 ||
        strcmp(argv[2], "--foreground") != 0) return 0;
    if (argc == 4 && strcmp(argv[3], "--debug") != 0) return 0;
    *debug = argc == 4;
    return 1;
}

int pm3000_acme_app_run(int argc, char **argv,
                        const struct pm3000_acme_app_paths *paths)
{
    struct pm3000_acme_runtime_config runtime;
    struct pm3000_acme_state state;
    struct pm3000_acme_client_config client_config;
    struct pm3000_acme_client_io io;
    struct pm3000_acme_transport transport;
    const char *name_pointers[PM3000_ACME_MAX_IDENTIFIERS];
    char account_url[PM3000_ACME_KID_MAX + 1U];
    unsigned int config_length = 0U;
    unsigned int index;
    int debug = 0;
    int account_status;
    int publish_status;
    int durability_uncertain = 0;
    int state_status;
    int client_status;
    int result = PM3000_ACME_APP_FAILED;
    if (paths == (const struct pm3000_acme_app_paths *)0 ||
        paths->state_root == (const char *)0 ||
        paths->challenge_webroot == (const char *)0 ||
        !arguments_valid(argc, argv, &debug)) return PM3000_ACME_APP_USAGE;
    state_status = pm3000_acme_state_open(paths->state_root, &state);
    if (state_status == PM3000_ACME_STATE_BUSY) return PM3000_ACME_APP_BUSY;
    if (state_status != PM3000_ACME_STATE_OK) {
        if (debug) fputs("acme.phase=state status=failed\n", stderr);
        return PM3000_ACME_APP_FAILED;
    }
    if (pm3000_acme_store_read_at(state.root_fd, "config.json",
                                  config_bytes, sizeof(config_bytes) - 1U,
                                  &config_length, 1) != PM3000_ACME_STORE_OK ||
        config_length == 0U || config_length >= sizeof(config_bytes)) {
        if (debug) fputs("acme.phase=config status=failed\n", stderr);
        goto done;
    }
    config_bytes[config_length] = '\0';
    if (pm3000_acme_config_parse(config_bytes, config_length, &runtime) !=
        PM3000_ACME_CONFIG_OK) {
        if (debug) fputs("acme.phase=config status=rejected\n", stderr);
        goto done;
    }
    if (!runtime.enabled) {
        if (debug) fputs("acme.phase=config status=disabled\n", stderr);
        result = PM3000_ACME_APP_DISABLED;
        goto done;
    }
    state_status = pm3000_acme_state_prepare_locked(&state);
    if (state_status == PM3000_ACME_STATE_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
    else if (state_status != PM3000_ACME_STATE_OK) {
        if (debug) fputs("acme.phase=state status=failed\n", stderr);
        goto done;
    }
    account_status = pm3000_acme_state_load_account_url(
        &state, account_url, sizeof(account_url));
    if (account_status != PM3000_ACME_STATE_OK &&
        account_status != PM3000_ACME_STATE_NOT_FOUND) {
        if (debug) fputs("acme.phase=account-state status=failed\n", stderr);
        goto done;
    }
    for (index = 0U; index < runtime.dns_name_count; ++index)
        name_pointers[index] = runtime.dns_names[index];
    memset(&client_config, 0, sizeof(client_config));
    client_config.directory_url = runtime.directory_url;
    client_config.existing_account_url =
        account_status == PM3000_ACME_STATE_OK ? account_url : (const char *)0;
    client_config.challenge_webroot = paths->challenge_webroot;
    client_config.dns_names = name_pointers;
    client_config.dns_name_count = runtime.dns_name_count;
    client_config.poll_attempts = PM3000_ACME_POLL_ATTEMPTS_MAX;
    client_config.account_key = &state.account_key;
    client_config.certificate_key = &state.certificate_key;
    transport.ca_file = runtime.ca_file;
    transport.timeout_seconds = 20U;
    transport.workspace = &transport_workspace;
    io.exchange = pm3000_acme_transport_exchange;
    io.sleep = sleep_seconds;
    io.context = &transport;
    if (debug) fputs("acme.phase=renew status=started\n", stderr);
    client_status = pm3000_acme_client_issue(
        &client_config, &io, &client_workspace, &client_result);
    if (client_status != PM3000_ACME_CLIENT_OK) {
        write_status(&state, "renew-failed");
        if (debug) fputs("acme.phase=renew status=failed\n", stderr);
        goto done;
    }
    account_status = pm3000_acme_state_store_account_url(
        &state, client_result.account_url);
    if (account_status == PM3000_ACME_STATE_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
    else if (account_status != PM3000_ACME_STATE_OK) {
        write_status(&state, "account-state-failed");
        if (debug) fputs("acme.phase=account-state status=failed\n", stderr);
        goto done;
    }
    publish_status = pm3000_acme_publish_certificate(
        state.root_fd, client_result.certificate_pem,
        client_result.certificate_length, runtime.ca_file,
        &state.certificate_key, name_pointers, runtime.dns_name_count);
    if (publish_status == PM3000_ACME_PUBLISH_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
    else if (publish_status != PM3000_ACME_PUBLISH_OK) {
        write_status(&state, "publish-failed");
        if (debug) fputs("acme.phase=publish status=failed\n", stderr);
        goto done;
    }
    if (durability_uncertain) {
        write_status(&state, "valid-durability-uncertain");
        if (debug)
            fputs("acme.phase=publish status=committed-durability-uncertain\n",
                  stderr);
        goto done;
    }
    write_status(&state, "valid");
    if (debug) fputs("acme.phase=publish status=complete\n", stderr);
    result = PM3000_ACME_APP_OK;
done:
    pm3000_acme_state_close(&state);
    return result;
}
