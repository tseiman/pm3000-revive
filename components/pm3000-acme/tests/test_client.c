#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_client.h"

#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

struct mock_state {
    const char *webroot;
    unsigned int nonce;
    unsigned int bad_nonce_sent;
    unsigned int account_requests;
    unsigned int challenge_triggered;
    unsigned int auth_requests;
    unsigned int challenge_requests;
    unsigned int auth_polls;
    unsigned int finalized;
    unsigned int order_polls;
    unsigned int sleeps;
    unsigned int always_pending;
};

static void copy_text(char *output, unsigned int capacity, const char *text)
{
    snprintf(output, capacity, "%s", text);
}

static int set_response(struct mock_state *state,
                        struct pm3000_acme_http_response *response,
                        unsigned char *body, unsigned int capacity,
                        unsigned int status, const char *location,
                        const char *json)
{
    size_t length = strlen(json);
    if (length + 1U > capacity) return -1;
    memset(response, 0, sizeof(*response));
    response->status_code = status;
    snprintf(response->replay_nonce, sizeof(response->replay_nonce),
             "bm9uY2Ut%u", ++state->nonce);
    if (location != NULL)
        copy_text(response->location, sizeof(response->location), location);
    memcpy(body, json, length + 1U);
    response->body_length = (unsigned int)length;
    return 0;
}

static int challenge_file_matches(const char *webroot)
{
    char path[512];
    char data[256];
    int fd;
    ssize_t amount;
    snprintf(path, sizeof(path), "%s/dG9rZW4", webroot);
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    amount = read(fd, data, sizeof(data) - 1U);
    close(fd);
    if (amount < 0) return 0;
    data[amount] = '\0';
    return strncmp(data, "dG9rZW4.", 8U) == 0 && strlen(data) > 20U;
}

static int mock_exchange(
    void *opaque, const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *request_body,
    unsigned int request_body_length,
    struct pm3000_acme_http_response *response,
    unsigned char *body, unsigned int capacity)
{
    struct mock_state *state = (struct mock_state *)opaque;
    (void)content_type;
    if (strcmp(url->path, "/directory") == 0 && strcmp(method, "GET") == 0)
        return set_response(state, response, body, capacity, 200U, NULL,
            "{\"newNonce\":\"https://localhost/nonce\","
            "\"newAccount\":\"https://localhost/account\","
            "\"newOrder\":\"https://localhost/new-order\"}");
    if (strcmp(url->path, "/nonce") == 0 && strcmp(method, "HEAD") == 0)
        return set_response(state, response, body, capacity, 204U, NULL, "");
    if (request_body == NULL || request_body_length == 0U ||
        request_body[0] != '{') return -1;
    if (strcmp(url->path, "/account") == 0) {
        ++state->account_requests;
        return set_response(state, response, body, capacity, 201U,
                            "https://localhost/account/1",
                            "{\"status\":\"valid\"}");
    }
    if (strcmp(url->path, "/new-order") == 0) {
        if (!state->bad_nonce_sent++)
            return set_response(state, response, body, capacity, 400U, NULL,
                "{\"type\":\"urn:ietf:params:acme:error:badNonce\"}");
        return set_response(state, response, body, capacity, 201U,
            "https://localhost/order/1",
            "{\"status\":\"pending\","
            "\"authorizations\":[\"https://localhost/auth/1\"],"
            "\"finalize\":\"https://localhost/finalize/1\"}");
    }
    if (strcmp(url->path, "/auth/1") == 0) {
        ++state->auth_requests;
        if (!state->challenge_triggered)
            return set_response(state, response, body, capacity, 200U, NULL,
                "{\"status\":\"pending\","
                "\"identifier\":{\"type\":\"dns\",\"value\":\"pdu1.tsei.mdn\"},"
                "\"challenges\":[{\"type\":\"http-01\","
                "\"url\":\"https://localhost/challenge/1\","
                "\"status\":\"pending\",\"token\":\"dG9rZW4\"}]}");
        ++state->auth_polls;
        if (state->always_pending || state->auth_polls == 1U)
            return set_response(state, response, body, capacity, 200U, NULL,
                "{\"status\":\"pending\","
                "\"identifier\":{\"type\":\"dns\",\"value\":\"pdu1.tsei.mdn\"},"
                "\"challenges\":[{\"type\":\"http-01\","
                "\"url\":\"https://localhost/challenge/1\","
                "\"status\":\"processing\",\"token\":\"dG9rZW4\"}]}");
        return set_response(state, response, body, capacity, 200U, NULL,
            "{\"status\":\"valid\","
            "\"identifier\":{\"type\":\"dns\",\"value\":\"pdu1.tsei.mdn\"},"
            "\"challenges\":[{\"type\":\"http-01\","
            "\"url\":\"https://localhost/challenge/1\","
            "\"status\":\"valid\",\"token\":\"dG9rZW4\"}]}");
    }
    if (strcmp(url->path, "/challenge/1") == 0) {
        ++state->challenge_requests;
        if (!challenge_file_matches(state->webroot)) return -1;
        state->challenge_triggered = 1U;
        return set_response(state, response, body, capacity, 200U, NULL,
                            "{\"status\":\"pending\"}");
    }
    if (strcmp(url->path, "/finalize/1") == 0) {
        state->finalized = 1U;
        return set_response(state, response, body, capacity, 200U, NULL,
            "{\"status\":\"processing\","
            "\"authorizations\":[\"https://localhost/auth/1\"],"
            "\"finalize\":\"https://localhost/finalize/1\"}");
    }
    if (strcmp(url->path, "/order/1") == 0) {
        if (!state->finalized)
            return set_response(state, response, body, capacity, 200U, NULL,
                "{\"status\":\"ready\","
                "\"authorizations\":[\"https://localhost/auth/1\"],"
                "\"finalize\":\"https://localhost/finalize/1\"}");
        ++state->order_polls;
        if (state->order_polls == 1U)
            return set_response(state, response, body, capacity, 200U, NULL,
                "{\"status\":\"processing\","
                "\"authorizations\":[\"https://localhost/auth/1\"],"
                "\"finalize\":\"https://localhost/finalize/1\"}");
        return set_response(state, response, body, capacity, 200U, NULL,
            "{\"status\":\"valid\","
            "\"authorizations\":[\"https://localhost/auth/1\"],"
            "\"finalize\":\"https://localhost/finalize/1\","
            "\"certificate\":\"https://localhost/cert/1\"}");
    }
    if (strcmp(url->path, "/cert/1") == 0)
        return set_response(state, response, body, capacity, 200U, NULL,
                            "-----BEGIN CERTIFICATE-----\nTEST\n-----END CERTIFICATE-----\n");
    return -1;
}

static int mock_sleep(void *opaque, unsigned int seconds)
{
    struct mock_state *state = (struct mock_state *)opaque;
    if (seconds == 0U || seconds > 60U) return -1;
    ++state->sleeps;
    return 0;
}

int main(void)
{
    static const char *names[] = {"pdu1.tsei.mdn"};
    char webroot[] = "build/client-challenge";
    char challenge_path[] = "build/client-challenge/dG9rZW4";
    struct pm3000_acme_key account_key = {0};
    struct pm3000_acme_key certificate_key = {0};
    struct pm3000_acme_client_config config;
    struct pm3000_acme_client_io io;
    static struct pm3000_acme_client_workspace workspace;
    static struct pm3000_acme_client_result result;
    struct mock_state state;
    int status;
    int timeout_status;

    unlink(challenge_path);
    rmdir(webroot);
    if (mkdir(webroot, 0755) != 0 ||
        pm3000_acme_crypto_key_load(
            "tests/fixtures/account-test-key.pem", &account_key) !=
            PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_crypto_key_load(
            "tests/fixtures/account-test-key.pem", &certificate_key) !=
            PM3000_ACME_CRYPTO_OK) return 2;
    memset(&state, 0, sizeof(state));
    state.webroot = webroot;
    memset(&config, 0, sizeof(config));
    config.directory_url = "https://localhost/directory";
    config.challenge_webroot = webroot;
    config.dns_names = names;
    config.dns_name_count = 1U;
    config.poll_attempts = 5U;
    config.account_key = &account_key;
    config.certificate_key = &certificate_key;
    io.exchange = mock_exchange;
    io.sleep = mock_sleep;
    io.context = &state;

    status = pm3000_acme_client_issue(&config, &io, &workspace, &result);
    if (status != PM3000_ACME_CLIENT_OK ||
        strcmp(result.account_url, "https://localhost/account/1") != 0 ||
        strstr((const char *)result.certificate_pem,
               "BEGIN CERTIFICATE") == NULL ||
        state.bad_nonce_sent != 2U || state.auth_polls != 2U ||
        state.order_polls != 2U || state.sleeps < 2U ||
        lstat(challenge_path, &(struct stat){0}) == 0) {
        fprintf(stderr,
                "client flow failed status=%d badNonce=%u authReq=%u challengeReq=%u authPolls=%u orderPolls=%u sleeps=%u\n",
                status, state.bad_nonce_sent, state.auth_requests,
                state.challenge_requests, state.auth_polls,
                state.order_polls, state.sleeps);
        pm3000_acme_crypto_key_free(&certificate_key);
        pm3000_acme_crypto_key_free(&account_key);
        unlink(challenge_path);
        rmdir(webroot);
        return 1;
    }

    memset(&state, 0, sizeof(state));
    state.webroot = webroot;
    state.always_pending = 1U;
    io.context = &state;
    config.poll_attempts = 1U;
    config.existing_account_url = "https://localhost/account/1";
    timeout_status = pm3000_acme_client_issue(
        &config, &io, &workspace, &result);
    pm3000_acme_crypto_key_free(&certificate_key);
    pm3000_acme_crypto_key_free(&account_key);
    if (timeout_status != PM3000_ACME_CLIENT_TIMEOUT ||
        state.account_requests != 0U ||
        lstat(challenge_path, &(struct stat){0}) == 0) {
        fprintf(stderr, "client timeout cleanup failed status=%d\n",
                timeout_status);
        unlink(challenge_path);
        rmdir(webroot);
        return 1;
    }
    rmdir(webroot);
    puts("client.tests.complete=yes");
    return 0;
}
