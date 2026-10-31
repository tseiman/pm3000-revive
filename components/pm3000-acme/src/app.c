#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_app.h"
#include "pm3000_acme_admin.h"
#include "pm3000_acme_certificate.h"
#include "pm3000_acme_client.h"
#include "pm3000_acme_config.h"
#include "pm3000_acme_json.h"
#include "pm3000_acme_publish.h"
#include "pm3000_acme_state.h"
#include "pm3000_acme_store.h"
#include "pm3000_acme_transport.h"

#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned char config_bytes[PM3000_ACME_JSON_MAX_BYTES + 1U];
static unsigned char admin_output[PM3000_ACME_ADMIN_OUTPUT_MAX];
static unsigned char admin_input[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
static unsigned char ca_input[PM3000_ACME_CA_BUNDLE_MAX + 1U];
static struct pm3000_acme_client_workspace client_workspace;
static struct pm3000_acme_client_result client_result;
static struct pm3000_acme_transport_workspace transport_workspace;

static int sleep_seconds(void *context, unsigned int seconds)
{
    (void)context;
    while (seconds != 0U) seconds = sleep(seconds);
    return 0;
}

static int arguments_valid(int argc, char **argv, int *debug,
                           int *startup_notify)
{
    if (argc != 3 && argc != 4) return 0;
    if (strcmp(argv[1], "renew") != 0 ||
        strcmp(argv[2], "--foreground") != 0) return 0;
    if (argc == 4 && strcmp(argv[3], "--debug") != 0 &&
        strcmp(argv[3], "--broker-startup-notify") != 0) return 0;
    *debug = argc == 4 && strcmp(argv[3], "--debug") == 0;
    *startup_notify = argc == 4 &&
                      strcmp(argv[3], "--broker-startup-notify") == 0;
    return 1;
}

static int startup_signal(int enabled, unsigned char value)
{
    ssize_t amount;
    if (!enabled) return 0;
    do {
        amount = write(3, &value, 1U);
    } while (amount < 0 && errno == EINTR);
    if (close(3) != 0) return -1;
    return amount == 1 ? 0 : -1;
}

static void record_failure(int root_fd, int debug,
                           enum pm3000_acme_failure_phase phase,
                           enum pm3000_acme_failure_reason reason,
                           unsigned int http_status_code,
                           enum pm3000_acme_problem problem)
{
    const char *phase_name = pm3000_acme_failure_phase_name(phase);
    const char *reason_name = pm3000_acme_failure_reason_name(reason);
    (void)pm3000_acme_admin_status_write_failure_at(
        root_fd, phase_name, reason_name);
    if (debug) {
        char diagnostic[160];
        struct pm3000_acme_client_result failure;
        memset(&failure, 0, sizeof(failure));
        failure.failure_phase = phase;
        failure.failure_reason = reason;
        failure.http_status_code = http_status_code;
        failure.problem = problem;
        if (pm3000_acme_failure_debug_format(
                &failure, diagnostic, sizeof(diagnostic)) == 0)
            fputs(diagnostic, stderr);
    }
}

int pm3000_acme_failure_debug_format(
    const struct pm3000_acme_client_result *failure,
    char *output, unsigned int output_capacity)
{
    int length;
    if (failure == (const struct pm3000_acme_client_result *)0 ||
        output == (char *)0 || output_capacity == 0U)
        return -1;
    if (failure->http_status_code != 0U)
        length = snprintf(output, output_capacity,
            "acme.failure phase=%s reason=%s status=%u problem=%s\n",
            pm3000_acme_failure_phase_name(failure->failure_phase),
            pm3000_acme_failure_reason_name(failure->failure_reason),
            failure->http_status_code,
            pm3000_acme_problem_name(failure->problem));
    else
        length = snprintf(output, output_capacity,
            "acme.failure phase=%s reason=%s\n",
            pm3000_acme_failure_phase_name(failure->failure_phase),
            pm3000_acme_failure_reason_name(failure->failure_reason));
    return length > 0 && (unsigned int)length < output_capacity ? 0 : -1;
}

static int write_standard_output(const unsigned char *data,
                                 unsigned int length)
{
    while (length != 0U) {
        ssize_t amount = write(STDOUT_FILENO, data, length);
        if (amount <= 0) return -1;
        data += (unsigned int)amount;
        length -= (unsigned int)amount;
    }
    return 0;
}

static int read_standard_input(unsigned char *data, unsigned int capacity,
                               unsigned int *length)
{
    unsigned int total = 0U;
    while (total < capacity) {
        ssize_t amount = read(STDIN_FILENO, data + total, capacity - total);
        if (amount == 0) break;
        if (amount < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += (unsigned int)amount;
    }
    *length = total;
    return 0;
}

static int run_read_only_admin(
    int argc, char **argv, const struct pm3000_acme_app_paths *paths,
    int *handled)
{
    unsigned int length = 0U;
    int admin_result;
    const char *state_root = paths->state_root;
    *handled = 1;
    if (argc == 3 && strcmp(argv[1], "config") == 0 &&
        strcmp(argv[2], "show") == 0)
        admin_result = pm3000_acme_admin_config_show(
            state_root, admin_output, sizeof(admin_output), &length);
    else if (argc == 3 && strcmp(argv[1], "config") == 0 &&
             strcmp(argv[2], "revision") == 0) {
        admin_result = pm3000_acme_admin_config_revision(
            state_root, paths->managed_ca_file, (char *)admin_output,
            sizeof(admin_output));
        if (admin_result == PM3000_ACME_ADMIN_OK) {
            admin_output[65] = '\"';
            admin_output[66] = '\n';
            length = 67U;
        }
    }
    else if (argc == 2 && strcmp(argv[1], "status") == 0)
        admin_result = pm3000_acme_admin_status(
            state_root, admin_output, sizeof(admin_output), &length);
    else if (argc == 3 && strcmp(argv[1], "bootstrap") == 0 &&
             strcmp(argv[2], "status") == 0)
        admin_result = pm3000_acme_admin_bootstrap_status(
            state_root, admin_output, sizeof(admin_output), &length);
    else if ((argc == 4 || argc == 6) &&
             strcmp(argv[1], "config") == 0 &&
             strcmp(argv[2], "replace") == 0 &&
             strcmp(argv[3], "--stdin") == 0 &&
             (argc == 4 || strcmp(argv[4], "--if-match") == 0 ||
              (strcmp(argv[4], "--if-none-match") == 0 &&
               strcmp(argv[5], "*") == 0))) {
        if (read_standard_input(admin_input, sizeof(admin_input), &length) != 0 ||
            length == 0U || length > PM3000_ACME_CONFIG_MAX_BYTES)
            return PM3000_ACME_APP_FAILED;
        if (argc == 4)
            admin_result = pm3000_acme_admin_config_replace(
                state_root, admin_input, length);
        else if (strcmp(argv[4], "--if-none-match") == 0)
            admin_result = pm3000_acme_admin_config_create_if_none_match(
                state_root, paths->managed_ca_file, admin_input, length);
        else
            admin_result = pm3000_acme_admin_config_replace_if_match(
                state_root, paths->managed_ca_file, admin_input, length,
                argv[5]);
        length = 0U;
    }
    else if ((argc == 4 || argc == 6) && strcmp(argv[1], "ca") == 0 &&
             strcmp(argv[2], "install") == 0 &&
             strcmp(argv[3], "--stdin") == 0 &&
             (argc == 4 || strcmp(argv[4], "--if-match") == 0 ||
              (strcmp(argv[4], "--if-none-match") == 0 &&
               strcmp(argv[5], "*") == 0))) {
        if (read_standard_input(ca_input, sizeof(ca_input), &length) != 0 ||
            length == 0U || length > PM3000_ACME_CA_BUNDLE_MAX)
            return PM3000_ACME_APP_FAILED;
        if (argc == 4)
            admin_result = pm3000_acme_admin_ca_install(
                state_root, paths->managed_ca_file, ca_input, length);
        else if (strcmp(argv[4], "--if-none-match") == 0)
            admin_result = pm3000_acme_admin_ca_create_if_none_match(
                state_root, paths->managed_ca_file, ca_input, length);
        else
            admin_result = pm3000_acme_admin_ca_install_if_match(
                state_root, paths->managed_ca_file, ca_input, length,
                argv[5]);
        length = 0U;
    }
    else {
        *handled = 0;
        return PM3000_ACME_APP_USAGE;
    }
    if (admin_result == PM3000_ACME_ADMIN_STALE)
        return PM3000_ACME_APP_STALE;
    if (admin_result == PM3000_ACME_ADMIN_NOT_FOUND)
        return PM3000_ACME_APP_NOT_FOUND;
    return admin_result == PM3000_ACME_ADMIN_OK &&
                   (length == 0U ||
                    write_standard_output(admin_output, length) == 0)
               ? PM3000_ACME_APP_OK : PM3000_ACME_APP_FAILED;
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
    int startup_notify = 0;
    int startup_notified = 0;
    int account_status;
    int publish_status;
    int durability_uncertain = 0;
    int state_status;
    int client_status;
    int handled = 0;
    int result = PM3000_ACME_APP_FAILED;
    if (paths == (const struct pm3000_acme_app_paths *)0 ||
        paths->state_root == (const char *)0 ||
        paths->challenge_webroot == (const char *)0 ||
        paths->managed_ca_file == (const char *)0)
        return PM3000_ACME_APP_USAGE;
    result = run_read_only_admin(argc, argv, paths, &handled);
    if (handled) return result;
    if (!arguments_valid(argc, argv, &debug, &startup_notify))
        return PM3000_ACME_APP_USAGE;
    state_status = pm3000_acme_state_open(paths->state_root, &state);
    if (state_status == PM3000_ACME_STATE_BUSY) {
        (void)startup_signal(startup_notify, 'B');
        return PM3000_ACME_APP_BUSY;
    }
    if (state_status != PM3000_ACME_STATE_OK) {
        if (debug) fputs("acme.phase=state status=failed\n", stderr);
        (void)startup_signal(startup_notify, 'F');
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
    state_status = pm3000_acme_admin_status_write_at(state.root_fd, "starting");
    if (state_status != PM3000_ACME_ADMIN_OK &&
        state_status != PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN) {
        if (debug) fputs("acme.phase=status status=failed\n", stderr);
        goto done;
    }
    if (state_status == PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
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
    state_status = pm3000_acme_admin_status_write_at(state.root_fd, "running");
    if (state_status != PM3000_ACME_ADMIN_OK &&
        state_status != PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN) {
        if (debug) fputs("acme.phase=status status=failed\n", stderr);
        goto done;
    }
    if (state_status == PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN) {
        (void)startup_signal(startup_notify, 'U');
        startup_notified = startup_notify;
        goto done;
    }
    if (startup_signal(startup_notify, 'A') != 0) {
        (void)pm3000_acme_admin_status_write_at(state.root_fd, "failed");
        startup_notified = startup_notify;
        goto done;
    }
    startup_notified = startup_notify;
    if (debug) fputs("acme.phase=renew status=started\n", stderr);
    client_status = pm3000_acme_client_issue(
        &client_config, &io, &client_workspace, &client_result);
    if (client_status != PM3000_ACME_CLIENT_OK) {
        record_failure(state.root_fd, debug, client_result.failure_phase,
                       client_result.failure_reason,
                       client_result.http_status_code, client_result.problem);
        goto done;
    }
    account_status = pm3000_acme_state_store_account_url(
        &state, client_result.account_url);
    if (account_status == PM3000_ACME_STATE_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
    else if (account_status != PM3000_ACME_STATE_OK) {
        record_failure(state.root_fd, debug, PM3000_ACME_PHASE_ACCOUNT,
                       PM3000_ACME_REASON_PUBLICATION, 0U,
                       PM3000_ACME_PROBLEM_NONE);
        goto done;
    }
    publish_status = pm3000_acme_publish_certificate(
        state.root_fd, client_result.certificate_pem,
        client_result.certificate_length, runtime.ca_file,
        &state.certificate_key, name_pointers, runtime.dns_name_count);
    if (publish_status == PM3000_ACME_PUBLISH_COMMITTED_UNCERTAIN)
        durability_uncertain = 1;
    else if (publish_status != PM3000_ACME_PUBLISH_OK) {
        record_failure(
            state.root_fd, debug,
            publish_status == PM3000_ACME_PUBLISH_REJECTED ?
                PM3000_ACME_PHASE_CERTIFICATE_VALIDATION :
                PM3000_ACME_PHASE_CERTIFICATE_PUBLICATION,
            publish_status == PM3000_ACME_PUBLISH_REJECTED ?
                PM3000_ACME_REASON_VALIDATION : PM3000_ACME_REASON_PUBLICATION,
            0U, PM3000_ACME_PROBLEM_NONE);
        goto done;
    }
    if (durability_uncertain) {
        (void)pm3000_acme_admin_status_write_at(
            state.root_fd, "durability_uncertain");
        if (debug)
            fputs("acme.phase=publish status=committed-durability-uncertain\n",
                  stderr);
        goto done;
    }
    if (pm3000_acme_admin_status_write_at(state.root_fd, "succeeded") !=
        PM3000_ACME_ADMIN_OK) {
        if (debug) fputs("acme.phase=status status=failed\n", stderr);
        goto done;
    }
    if (debug) fputs("acme.phase=publish status=complete\n", stderr);
    result = PM3000_ACME_APP_OK;
done:
    if (startup_notify && !startup_notified)
        (void)startup_signal(1, 'F');
    pm3000_acme_state_close(&state);
    return result;
}
