#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_app.h"
#include "pm3000_acme_admin.h"
#include "pm3000_acme_store.h"

#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int main(void)
{
    char root[] = "build/app-test-XXXXXX";
    char challenge[] = "build/app-challenge-XXXXXX";
    char bootstrap_root[] = "build/app-bootstrap-test-XXXXXX";
    char bootstrap_challenge[] = "build/app-bootstrap-challenge-XXXXXX";
    char key_path[256];
    char trust_path[256];
    struct pm3000_acme_app_paths paths;
    char *renew[] = { (char *)"pm3000-acme", (char *)"renew",
                      (char *)"--foreground", (char *)"--debug" };
    char *broker_renew[] = { (char *)"pm3000-acme", (char *)"renew",
                             (char *)"--foreground",
                             (char *)"--broker-startup-notify" };
    char *bad[] = { (char *)"pm3000-acme", (char *)"shell" };
    char *show[] = { (char *)"pm3000-acme", (char *)"config",
                     (char *)"show" };
    char *revision_command[] = { (char *)"pm3000-acme", (char *)"config",
                                 (char *)"revision" };
    char *status[] = { (char *)"pm3000-acme", (char *)"status" };
    char *replace[] = { (char *)"pm3000-acme", (char *)"config",
                        (char *)"replace", (char *)"--stdin" };
    char *install_ca[] = { (char *)"pm3000-acme", (char *)"ca",
                           (char *)"install", (char *)"--stdin" };
    char *conditional_replace[] = {
        (char *)"pm3000-acme", (char *)"config", (char *)"replace",
        (char *)"--stdin", (char *)"--if-match",
        (char *)"\"2393c85658c6a5f3aaa7d5b04aec9a099ad3c98d28f091b49adf803fe771d208\""
    };
    char *conditional_ca[] = {
        (char *)"pm3000-acme", (char *)"ca", (char *)"install",
        (char *)"--stdin", (char *)"--if-match",
        (char *)"\"2393c85658c6a5f3aaa7d5b04aec9a099ad3c98d28f091b49adf803fe771d208\""
    };
    char *create_config[] = {
        (char *)"pm3000-acme", (char *)"config", (char *)"replace",
        (char *)"--stdin", (char *)"--if-none-match", (char *)"*"
    };
    char *create_ca[] = {
        (char *)"pm3000-acme", (char *)"ca", (char *)"install",
        (char *)"--stdin", (char *)"--if-none-match", (char *)"*"
    };
    int input_pipe[2];
    int output_pipe[2];
    int startup_pipe[2];
    int startup_read;
    int saved_stdout;
    char revision_output[PM3000_ACME_ADMIN_ETAG_BYTES + 1U];
    char diagnostic[128];
    struct pm3000_acme_client_result diagnostic_result;
    ssize_t revision_length;
    unsigned char ca_bundle[65536U];
    size_t ca_length;
    FILE *ca_file;
    static const unsigned char disabled[] =
        "{\"enabled\":false,\"directory_url\":\"https://acme.example.test/d\","
        "\"ca_file\":\"/etc/CA/root.pem\",\"dns_names\":[\"pdu1.tsei.mdn\"]}";
    static const unsigned char replacement[] =
        "{\"enabled\":false,\"directory_url\":\"https://acme.example.test/new\","
        "\"ca_file\":\"/etc/CA/root.pem\",\"dns_names\":[\"pdu1.tsei.mdn\"]}";
    memset(&diagnostic_result, 0, sizeof(diagnostic_result));
    diagnostic_result.failure_phase = PM3000_ACME_PHASE_CHALLENGE_ACCEPTANCE;
    diagnostic_result.failure_reason = PM3000_ACME_REASON_HTTP;
    diagnostic_result.http_status_code = 400U;
    diagnostic_result.problem = PM3000_ACME_PROBLEM_INCORRECT_RESPONSE;
    if (pm3000_acme_failure_debug_format(
            &diagnostic_result, diagnostic, sizeof(diagnostic)) != 0 ||
        strcmp(diagnostic,
               "acme.failure phase=challenge_acceptance reason=http status=400 problem=incorrect_response\n") != 0) {
        fprintf(stderr, "closed failure diagnostic formatting failed\n");
        return 1;
    }
    if (mkdtemp(root) == NULL || mkdtemp(challenge) == NULL ||
        chmod(root, 0700) != 0 || chmod(challenge, 0700) != 0 ||
        snprintf(trust_path, sizeof(trust_path), "%s/trust", root) < 0 ||
        mkdir(trust_path, 0700) != 0 ||
        pm3000_acme_store_write(root, "config.json", disabled,
                                sizeof(disabled) - 1U, 0600) !=
            PM3000_ACME_STORE_OK) return 2;
    paths.state_root = root;
    paths.challenge_webroot = challenge;
    paths.managed_ca_file = "/test/trust/managed-ca.pem";
    if (pipe(output_pipe) != 0 || (saved_stdout = dup(STDOUT_FILENO)) < 0 ||
        dup2(output_pipe[1], STDOUT_FILENO) < 0 || close(output_pipe[1]) != 0 ||
        pm3000_acme_app_run(3, revision_command, &paths) !=
            PM3000_ACME_APP_OK ||
        dup2(saved_stdout, STDOUT_FILENO) < 0 || close(saved_stdout) != 0 ||
        (revision_length = read(output_pipe[0], revision_output,
                                sizeof(revision_output))) != 67 ||
        close(output_pipe[0]) != 0 ||
        memcmp(revision_output,
               "\"2393c85658c6a5f3aaa7d5b04aec9a099ad3c98d28f091b49adf803fe771d208\"\n",
               67U) != 0 || pipe(input_pipe) != 0 ||
        write(input_pipe[1], replacement, sizeof(replacement) - 1U) !=
            (ssize_t)(sizeof(replacement) - 1U) ||
        close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
        close(input_pipe[0]) != 0 ||
        pm3000_acme_app_run(2, bad, &paths) != PM3000_ACME_APP_USAGE ||
        pm3000_acme_app_run(3, show, &paths) != PM3000_ACME_APP_OK ||
        pm3000_acme_app_run(2, status, &paths) != PM3000_ACME_APP_OK ||
        pm3000_acme_app_run(4, replace, &paths) != PM3000_ACME_APP_OK) {
        fprintf(stderr, "app argument/configuration contract failed\n");
        return 1;
    }
    if (pipe(input_pipe) != 0 ||
        write(input_pipe[1], disabled, sizeof(disabled) - 1U) !=
            (ssize_t)(sizeof(disabled) - 1U) ||
        close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
        close(input_pipe[0]) != 0 ||
        pm3000_acme_app_run(6, conditional_replace, &paths) !=
            PM3000_ACME_APP_STALE) {
        fprintf(stderr, "conditional replacement stale exit failed\n");
        return 1;
    }
    ca_file = fopen("tests/fixtures/tls/ca.pem", "rb");
    if (ca_file == NULL) return 2;
    ca_length = fread(ca_bundle, 1U, sizeof(ca_bundle), ca_file);
    if (ferror(ca_file) || !feof(ca_file) || fclose(ca_file) != 0 ||
        ca_length == 0U) return 2;
    if (mkdtemp(bootstrap_root) == NULL || mkdtemp(bootstrap_challenge) == NULL ||
        chmod(bootstrap_root, 0700) != 0 || chmod(bootstrap_challenge, 0700) != 0 ||
        snprintf(trust_path, sizeof(trust_path), "%s/trust", bootstrap_root) < 0 ||
        mkdir(trust_path, 0700) != 0)
        return 2;
    paths.state_root = bootstrap_root;
    paths.challenge_webroot = bootstrap_challenge;
    paths.managed_ca_file = "/test/trust/managed-ca.pem";
    {
        static const unsigned char bootstrap_config[] =
            "{\"enabled\":false,\"directory_url\":\"https://operator.example.test/directory\","
            "\"ca_file\":\"/test/trust/managed-ca.pem\",\"dns_names\":[\"pdu.operator.example.test\"]}";
        if (pm3000_acme_app_run(3, show, &paths) != PM3000_ACME_APP_NOT_FOUND ||
            pipe(input_pipe) != 0 ||
            write(input_pipe[1], ca_bundle, ca_length) != (ssize_t)ca_length ||
            close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            close(input_pipe[0]) != 0 ||
            pm3000_acme_app_run(6, create_ca, &paths) != PM3000_ACME_APP_OK ||
            pipe(input_pipe) != 0 ||
            write(input_pipe[1], bootstrap_config, sizeof(bootstrap_config) - 1U) !=
                (ssize_t)(sizeof(bootstrap_config) - 1U) ||
            close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
            close(input_pipe[0]) != 0 ||
            pm3000_acme_app_run(6, create_config, &paths) != PM3000_ACME_APP_OK ||
            pm3000_acme_app_run(3, show, &paths) != PM3000_ACME_APP_OK) {
            fprintf(stderr, "first-run CLI bootstrap failed\n");
            return 1;
        }
    }
    paths.state_root = root;
    paths.challenge_webroot = challenge;
    paths.managed_ca_file = "/test/trust/managed-ca.pem";
    if (pipe(input_pipe) != 0 ||
        write(input_pipe[1], ca_bundle, ca_length) != (ssize_t)ca_length ||
        close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
        close(input_pipe[0]) != 0 ||
        pm3000_acme_app_run(6, conditional_ca, &paths) !=
            PM3000_ACME_APP_STALE) {
        fprintf(stderr, "conditional CA stale exit failed\n");
        return 1;
    }
    if (pipe(input_pipe) != 0 ||
        write(input_pipe[1], ca_bundle, ca_length) != (ssize_t)ca_length ||
        close(input_pipe[1]) != 0 || dup2(input_pipe[0], STDIN_FILENO) < 0 ||
        close(input_pipe[0]) != 0 ||
        pm3000_acme_app_run(4, install_ca, &paths) != PM3000_ACME_APP_OK ||
        pm3000_acme_app_run(4, renew, &paths) != PM3000_ACME_APP_DISABLED ||
        snprintf(key_path, sizeof(key_path), "%s/account-key.pem", root) < 0 ||
        access(key_path, F_OK) == 0) {
        fprintf(stderr, "app argument/disabled contract failed\n");
        return 1;
    }
    if (pipe(startup_pipe) != 0 ||
        (startup_read = fcntl(startup_pipe[0], F_DUPFD, 10)) < 0 ||
        close(startup_pipe[0]) != 0 || dup2(startup_pipe[1], 3) < 0 ||
        close(startup_pipe[1]) != 0 ||
        pm3000_acme_app_run(4, broker_renew, &paths) !=
            PM3000_ACME_APP_DISABLED ||
        read(startup_read, key_path, 1U) != 1 || key_path[0] != 'F' ||
        close(startup_read) != 0) {
        fprintf(stderr, "broker startup disabled notification failed\n");
        return 1;
    }
    puts("app.tests.complete=yes");
    return 0;
}
