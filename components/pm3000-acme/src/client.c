#include "pm3000_acme_client.h"
#include "pm3000_acme_base64url.h"
#include "pm3000_acme_challenge.h"
#include "pm3000_acme_json.h"
#include "pm3000_acme_protocol.h"
#include "pm3000_acme_url.h"

struct client_state {
    const struct pm3000_acme_client_config *config;
    const struct pm3000_acme_client_io *io;
    struct pm3000_acme_client_workspace *workspace;
    struct pm3000_acme_client_result *result;
    struct pm3000_acme_url origin;
    struct pm3000_acme_directory directory;
    char nonce[PM3000_ACME_HTTP_NONCE_MAX + 1U];
    char kid[PM3000_ACME_KID_MAX + 1U];
    char thumbprint[PM3000_ACME_THUMBPRINT_MAX + 1U];
    enum pm3000_acme_failure_phase phase;
};

static int text_equal(const char *left, const char *right);

const char *pm3000_acme_failure_phase_name(enum pm3000_acme_failure_phase phase)
{
    static const char *const names[] = {
        "none", "directory", "nonce", "account", "order", "authorization",
        "challenge_publication", "challenge_acceptance", "challenge_poll",
        "finalize", "certificate_download", "certificate_validation",
        "certificate_publication"
    };
    return (unsigned int)phase < sizeof(names) / sizeof(names[0]) ?
           names[(unsigned int)phase] : "none";
}

const char *pm3000_acme_failure_reason_name(enum pm3000_acme_failure_reason reason)
{
    static const char *const names[] = {
        "none", "tls", "http", "parse", "io", "rejected", "timeout",
        "validation", "publication"
    };
    return (unsigned int)reason < sizeof(names) / sizeof(names[0]) ?
           names[(unsigned int)reason] : "none";
}

const char *pm3000_acme_problem_name(enum pm3000_acme_problem problem)
{
    static const char *const names[] = {
        "none", "unauthorized", "connection", "dns", "malformed",
        "rejected_identifier", "rate_limited", "server_internal", "tls",
        "incorrect_response", "order_not_ready", "unknown"
    };
    return (unsigned int)problem < sizeof(names) / sizeof(names[0]) ?
           names[(unsigned int)problem] : "unknown";
}

static enum pm3000_acme_problem classify_problem(
    const unsigned char *body, unsigned int length)
{
    static const char prefix[] = "urn:ietf:params:acme:error:";
    static const struct problem_mapping {
        const char *type;
        enum pm3000_acme_problem problem;
    } allowed[] = {
        {"unauthorized", PM3000_ACME_PROBLEM_UNAUTHORIZED},
        {"connection", PM3000_ACME_PROBLEM_CONNECTION},
        {"dns", PM3000_ACME_PROBLEM_DNS},
        {"malformed", PM3000_ACME_PROBLEM_MALFORMED},
        {"rejectedIdentifier", PM3000_ACME_PROBLEM_REJECTED_IDENTIFIER},
        {"rateLimited", PM3000_ACME_PROBLEM_RATE_LIMITED},
        {"serverInternal", PM3000_ACME_PROBLEM_SERVER_INTERNAL},
        {"tls", PM3000_ACME_PROBLEM_TLS},
        {"incorrectResponse", PM3000_ACME_PROBLEM_INCORRECT_RESPONSE},
        {"orderNotReady", PM3000_ACME_PROBLEM_ORDER_NOT_READY}
    };
    struct pm3000_acme_json_document document;
    char type[96];
    int token;
    unsigned int index;
    unsigned int prefix_length = (unsigned int)(sizeof(prefix) - 1U);
    if (pm3000_acme_json_parse(body, length, &document) != PM3000_ACME_JSON_OK ||
        document.tokens[0].type != PM3000_ACME_JSON_OBJECT ||
        pm3000_acme_json_object_get(&document, 0, "type", &token) !=
            PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(&document, token, type, sizeof(type)) !=
            PM3000_ACME_JSON_OK)
        return PM3000_ACME_PROBLEM_UNKNOWN;
    for (index = 0U; index < sizeof(allowed) / sizeof(allowed[0]); ++index) {
        unsigned int offset = 0U;
        while (offset < prefix_length && type[offset] == prefix[offset]) ++offset;
        if (offset == prefix_length &&
            text_equal(type + prefix_length, allowed[index].type))
            return allowed[index].problem;
    }
    return PM3000_ACME_PROBLEM_UNKNOWN;
}

static int fail(struct client_state *state, int status,
                enum pm3000_acme_failure_reason reason)
{
    state->result->failure_phase = state->phase;
    state->result->failure_reason = reason;
    return status;
}

static int fail_http(struct client_state *state, int status,
                     const struct pm3000_acme_http_response *response)
{
    state->result->http_status_code = response->status_code;
    state->result->problem = classify_problem(
        state->workspace->response_body, response->body_length);
    return fail(state, status, PM3000_ACME_REASON_HTTP);
}

static void clear_result(struct pm3000_acme_client_result *result)
{
    result->account_url[0] = '\0';
    result->certificate_pem[0] = '\0';
    result->certificate_length = 0U;
    result->failure_phase = PM3000_ACME_PHASE_NONE;
    result->failure_reason = PM3000_ACME_REASON_NONE;
    result->http_status_code = 0U;
    result->problem = PM3000_ACME_PROBLEM_NONE;
}

static int copy_text(char *output, unsigned int capacity, const char *input)
{
    unsigned int index = 0U;
    if (output == (char *)0 || input == (const char *)0 || capacity == 0U)
        return 0;
    while (input[index] != '\0') {
        if (index + 1U >= capacity) {
            output[0] = '\0';
            return 0;
        }
        output[index] = input[index];
        ++index;
    }
    output[index] = '\0';
    return 1;
}

static unsigned int text_length(const char *text)
{
    unsigned int length = 0U;
    while (text[length] != '\0') ++length;
    return length;
}

static int text_equal(const char *left, const char *right)
{
    unsigned int index = 0U;
    while (left[index] != '\0' && right[index] != '\0') {
        if (left[index] != right[index]) return 0;
        ++index;
    }
    return left[index] == right[index];
}

static int exchange(struct client_state *state, const char *method,
                    const struct pm3000_acme_url *url,
                    const char *content_type,
                    const unsigned char *request_body,
                    unsigned int request_body_length,
                    struct pm3000_acme_http_response *response)
{
    int exchange_result = state->io->exchange(
            state->io->context, method, url, content_type, request_body,
            request_body_length, response, state->workspace->response_body,
            sizeof(state->workspace->response_body));
    if (exchange_result != PM3000_ACME_EXCHANGE_OK)
        return fail(state, PM3000_ACME_CLIENT_IO,
                    exchange_result == PM3000_ACME_EXCHANGE_HTTP ?
                    PM3000_ACME_REASON_PARSE : PM3000_ACME_REASON_TLS);
    if (response->body_length > PM3000_ACME_HTTP_BODY_MAX)
        return fail(state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    return PM3000_ACME_CLIENT_OK;
}

static int signed_post(struct client_state *state, const char *target_text,
                       const struct pm3000_acme_url *target,
                       const char *kid, const unsigned char *payload,
                       unsigned int payload_length,
                       struct pm3000_acme_http_response *response)
{
    unsigned int attempt;
    for (attempt = 0U; attempt < 2U; ++attempt) {
        if (pm3000_acme_jws_create(
                state->config->account_key, state->nonce, target_text, kid,
                payload, payload_length, state->workspace->jws,
                sizeof(state->workspace->jws)) != PM3000_ACME_JWS_OK)
            return fail(state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
        if (exchange(state, "POST", target, "application/jose+json",
                     (const unsigned char *)state->workspace->jws,
                     text_length(state->workspace->jws),
                     response) != PM3000_ACME_CLIENT_OK)
            return PM3000_ACME_CLIENT_IO;
        if (response->replay_nonce[0] == '\0' ||
            !copy_text(state->nonce, sizeof(state->nonce),
                       response->replay_nonce))
            return fail(state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
        if (response->status_code == 400U && attempt == 0U &&
            pm3000_acme_error_is_bad_nonce(
                state->workspace->response_body, response->body_length))
            continue;
        return PM3000_ACME_CLIENT_OK;
    }
    return fail(state, PM3000_ACME_CLIENT_REJECTED,
                PM3000_ACME_REASON_REJECTED);
}

static int parse_same_origin_url(struct client_state *state, const char *text,
                                 struct pm3000_acme_url *url)
{
    if (text[0] == '\0' || pm3000_acme_url_parse(text, url) != PM3000_ACME_URL_OK ||
        !pm3000_acme_url_same_origin(&state->origin, url))
        return 0;
    return 1;
}

static int configured_identifier(struct client_state *state, const char *name,
                                 unsigned int *matched_index)
{
    unsigned int index;
    char normalized[PM3000_ACME_HOST_MAX + 1U];
    for (index = 0U; index < state->config->dns_name_count; ++index) {
        if (pm3000_acme_dns_name_normalize(
                state->config->dns_names[index], normalized,
                sizeof(normalized)) == PM3000_ACME_URL_OK &&
            text_equal(normalized, name)) {
            *matched_index = index;
            return 1;
        }
    }
    return 0;
}

static int authorize_one(struct client_state *state, const char *url_text,
                         unsigned int *identifier_index)
{
    struct pm3000_acme_url url;
    struct pm3000_acme_http_response response;
    struct pm3000_acme_authorization authorization;
    unsigned int attempt;
    int published = 0;
    char published_token[PM3000_ACME_TOKEN_MAX + 1U];
    int result = PM3000_ACME_CLIENT_PROTOCOL;
    published_token[0] = '\0';
    state->phase = PM3000_ACME_PHASE_AUTHORIZATION;
    if (!parse_same_origin_url(state, url_text, &url))
        return fail(state, result, PM3000_ACME_REASON_PARSE);
    if (signed_post(state, url_text, &url, state->kid,
                    (const unsigned char *)"", 0U, &response) !=
            PM3000_ACME_CLIENT_OK)
        return result;
    if (response.status_code != 200U)
        return fail_http(state, result, &response);
    if (pm3000_acme_authorization_parse(
            state->workspace->response_body, response.body_length,
            &state->origin, &authorization) != PM3000_ACME_PROTOCOL_OK ||
        !configured_identifier(state, authorization.identifier,
                               identifier_index))
        return fail(state, result, PM3000_ACME_REASON_PARSE);
    if (authorization.status == PM3000_ACME_STATUS_VALID)
        return PM3000_ACME_CLIENT_OK;
    if (authorization.status != PM3000_ACME_STATUS_PENDING)
        return fail(state, PM3000_ACME_CLIENT_REJECTED,
                    PM3000_ACME_REASON_REJECTED);
    state->phase = PM3000_ACME_PHASE_CHALLENGE_PUBLICATION;
    if (pm3000_acme_challenge_publish(
            state->config->challenge_webroot, authorization.challenge.token,
            state->thumbprint) != PM3000_ACME_CHALLENGE_OK)
        return fail(state, result, PM3000_ACME_REASON_IO);
    published = 1;
    if (!copy_text(published_token, sizeof(published_token),
                   authorization.challenge.token)) {
        (void)fail(state, result, PM3000_ACME_REASON_PARSE);
        goto cleanup;
    }
    state->phase = PM3000_ACME_PHASE_CHALLENGE_ACCEPTANCE;
    if (signed_post(state, authorization.challenge.url_text,
                    &authorization.challenge.url, state->kid,
                    (const unsigned char *)"{}", 2U, &response) !=
            PM3000_ACME_CLIENT_OK)
        goto cleanup;
    if (response.status_code != 200U && response.status_code != 202U) {
        (void)fail_http(state, result, &response);
        goto cleanup;
    }
    state->phase = PM3000_ACME_PHASE_CHALLENGE_POLL;
    for (attempt = 0U; attempt < state->config->poll_attempts; ++attempt) {
        if (state->io->sleep(state->io->context, 1U) != 0) {
            result = fail(state, PM3000_ACME_CLIENT_IO, PM3000_ACME_REASON_IO);
            goto cleanup;
        }
        if (signed_post(state, url_text, &url, state->kid,
                        (const unsigned char *)"", 0U, &response) !=
                PM3000_ACME_CLIENT_OK)
            goto cleanup;
        if (response.status_code != 200U) {
            (void)fail_http(state, result, &response);
            goto cleanup;
        }
        if (pm3000_acme_authorization_parse(
                state->workspace->response_body, response.body_length,
                &state->origin, &authorization) != PM3000_ACME_PROTOCOL_OK) {
            (void)fail(state, result, PM3000_ACME_REASON_PARSE);
            goto cleanup;
        }
        if (authorization.status == PM3000_ACME_STATUS_VALID) {
            result = PM3000_ACME_CLIENT_OK;
            goto cleanup;
        }
        if (authorization.status != PM3000_ACME_STATUS_PENDING &&
            authorization.status != PM3000_ACME_STATUS_PROCESSING) {
            result = fail(state, PM3000_ACME_CLIENT_REJECTED,
                          PM3000_ACME_REASON_REJECTED);
            goto cleanup;
        }
    }
    result = fail(state, PM3000_ACME_CLIENT_TIMEOUT,
                  PM3000_ACME_REASON_TIMEOUT);
cleanup:
    if (published && pm3000_acme_challenge_remove(
            state->config->challenge_webroot, published_token) !=
            PM3000_ACME_CHALLENGE_OK && result == PM3000_ACME_CLIENT_OK)
        result = fail(state, PM3000_ACME_CLIENT_IO, PM3000_ACME_REASON_IO);
    return result;
}

static int poll_order(struct client_state *state, const char *order_text,
                      const struct pm3000_acme_url *order_url,
                      int before_finalize, struct pm3000_acme_order *order)
{
    struct pm3000_acme_http_response response;
    unsigned int attempt;
    for (attempt = 0U; attempt < state->config->poll_attempts; ++attempt) {
        if (attempt != 0U && state->io->sleep(state->io->context, 1U) != 0)
            return fail(state, PM3000_ACME_CLIENT_IO, PM3000_ACME_REASON_IO);
        if (signed_post(state, order_text, order_url, state->kid,
                        (const unsigned char *)"", 0U, &response) !=
                PM3000_ACME_CLIENT_OK)
            return PM3000_ACME_CLIENT_PROTOCOL;
        if (response.status_code != 200U)
            return fail_http(state, PM3000_ACME_CLIENT_PROTOCOL, &response);
        if (pm3000_acme_order_parse(state->workspace->response_body,
                                    response.body_length, &state->origin,
                                    order) != PM3000_ACME_PROTOCOL_OK)
            return fail(state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
        if (before_finalize && order->status == PM3000_ACME_STATUS_READY)
            return PM3000_ACME_CLIENT_OK;
        if (!before_finalize && order->status == PM3000_ACME_STATUS_VALID &&
            order->have_certificate)
            return PM3000_ACME_CLIENT_OK;
        if (order->status == PM3000_ACME_STATUS_INVALID)
            return fail(state, PM3000_ACME_CLIENT_REJECTED,
                        PM3000_ACME_REASON_REJECTED);
        if (order->status != PM3000_ACME_STATUS_PENDING &&
            order->status != PM3000_ACME_STATUS_PROCESSING &&
            !(before_finalize && order->status == PM3000_ACME_STATUS_VALID))
            return fail(state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
    }
    return fail(state, PM3000_ACME_CLIENT_TIMEOUT,
                PM3000_ACME_REASON_TIMEOUT);
}

int pm3000_acme_client_issue(
    const struct pm3000_acme_client_config *config,
    const struct pm3000_acme_client_io *io,
    struct pm3000_acme_client_workspace *workspace,
    struct pm3000_acme_client_result *result)
{
    struct client_state state;
    struct pm3000_acme_http_response response;
    struct pm3000_acme_order order;
    struct pm3000_acme_url order_url;
    char order_text[PM3000_ACME_URL_TEXT_MAX + 1U];
    unsigned int payload_length;
    unsigned int csr_length;
    unsigned int index;
    unsigned int identifier_index;
    unsigned char matched[PM3000_ACME_MAX_IDENTIFIERS];
    int status;
    if (result != (struct pm3000_acme_client_result *)0) clear_result(result);
    if (config == (const struct pm3000_acme_client_config *)0 ||
        io == (const struct pm3000_acme_client_io *)0 ||
        workspace == (struct pm3000_acme_client_workspace *)0 ||
        result == (struct pm3000_acme_client_result *)0 ||
        config->directory_url == (const char *)0 ||
        config->challenge_webroot == (const char *)0 ||
        config->dns_names == (const char *const *)0 ||
        config->dns_name_count == 0U ||
        config->dns_name_count > PM3000_ACME_MAX_IDENTIFIERS ||
        config->poll_attempts == 0U ||
        config->poll_attempts > PM3000_ACME_POLL_ATTEMPTS_MAX ||
        config->account_key == (struct pm3000_acme_key *)0 ||
        config->certificate_key == (struct pm3000_acme_key *)0 ||
        io->exchange == (pm3000_acme_exchange_fn)0 ||
        io->sleep == (pm3000_acme_sleep_fn)0)
        return PM3000_ACME_CLIENT_INVALID;
    state.config = config;
    state.io = io;
    state.workspace = workspace;
    state.result = result;
    state.phase = PM3000_ACME_PHASE_DIRECTORY;
    state.nonce[0] = '\0';
    state.kid[0] = '\0';
    if (pm3000_acme_url_parse(config->directory_url, &state.origin) !=
            PM3000_ACME_URL_OK ||
        pm3000_acme_crypto_thumbprint(
            config->account_key, state.thumbprint,
            sizeof(state.thumbprint)) != PM3000_ACME_CRYPTO_OK)
        return fail(&state, PM3000_ACME_CLIENT_INVALID,
                    PM3000_ACME_REASON_PARSE);

    if (exchange(&state, "GET", &state.origin, (const char *)0,
                 (const unsigned char *)0, 0U, &response) !=
            PM3000_ACME_CLIENT_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (response.status_code != 200U)
        return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
    if (pm3000_acme_directory_parse(workspace->response_body,
                                    response.body_length, &state.origin,
                                    &state.directory) != PM3000_ACME_PROTOCOL_OK)
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    state.phase = PM3000_ACME_PHASE_NONCE;
    if (exchange(&state, "HEAD", &state.directory.new_nonce,
                 (const char *)0, (const unsigned char *)0, 0U, &response) !=
            PM3000_ACME_CLIENT_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (response.status_code != 200U && response.status_code != 204U)
        return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
    if (response.replay_nonce[0] == '\0' ||
        !copy_text(state.nonce, sizeof(state.nonce), response.replay_nonce))
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);

    state.phase = PM3000_ACME_PHASE_ACCOUNT;
    if (config->existing_account_url != (const char *)0 &&
        config->existing_account_url[0] != '\0') {
        if (!copy_text(state.kid, sizeof(state.kid),
                       config->existing_account_url) ||
            !parse_same_origin_url(&state, state.kid, &order_url) ||
            !copy_text(result->account_url, sizeof(result->account_url),
                       state.kid))
            return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
    } else {
        if (signed_post(&state, state.directory.new_account_text,
                        &state.directory.new_account, (const char *)0,
                        (const unsigned char *)
                            "{\"termsOfServiceAgreed\":true}",
                        29U, &response) != PM3000_ACME_CLIENT_OK)
            return PM3000_ACME_CLIENT_PROTOCOL;
        if (response.status_code != 200U && response.status_code != 201U)
            return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
        if (response.location[0] == '\0' ||
            pm3000_acme_account_parse(workspace->response_body,
                                      response.body_length) != PM3000_ACME_PROTOCOL_OK ||
            !copy_text(state.kid, sizeof(state.kid), response.location) ||
            !parse_same_origin_url(&state, state.kid, &order_url) ||
            !copy_text(result->account_url, sizeof(result->account_url),
                       state.kid))
            return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
    }

    state.phase = PM3000_ACME_PHASE_ORDER;
    if (pm3000_acme_build_order_payload(
            config->dns_names, config->dns_name_count, workspace->payload,
            sizeof(workspace->payload), &payload_length) != PM3000_ACME_PROTOCOL_OK)
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    if (signed_post(&state, state.directory.new_order_text,
                    &state.directory.new_order, state.kid,
                    (const unsigned char *)workspace->payload, payload_length,
                    &response) != PM3000_ACME_CLIENT_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (response.status_code != 200U && response.status_code != 201U)
        return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
    if (!parse_same_origin_url(&state, response.location, &order_url) ||
        !copy_text(order_text, sizeof(order_text), response.location) ||
        pm3000_acme_order_parse(workspace->response_body,
                                response.body_length, &state.origin, &order) !=
            PM3000_ACME_PROTOCOL_OK ||
        order.authorization_count != config->dns_name_count)
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    for (index = 0U; index < PM3000_ACME_MAX_IDENTIFIERS; ++index)
        matched[index] = 0U;
    for (index = 0U; index < order.authorization_count; ++index) {
        status = authorize_one(&state, order.authorization_text[index],
                               &identifier_index);
        if (status != PM3000_ACME_CLIENT_OK) return status;
        if (identifier_index >= config->dns_name_count || matched[identifier_index]) {
            state.phase = PM3000_ACME_PHASE_AUTHORIZATION;
            return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                        PM3000_ACME_REASON_PARSE);
        }
        matched[identifier_index] = 1U;
    }

    state.phase = PM3000_ACME_PHASE_ORDER;
    status = poll_order(&state, order_text, &order_url, 1, &order);
    if (status != PM3000_ACME_CLIENT_OK) return status;
    state.phase = PM3000_ACME_PHASE_FINALIZE;
    if (pm3000_acme_crypto_csr_der(
            config->certificate_key, config->dns_names,
            config->dns_name_count, workspace->csr_der,
            sizeof(workspace->csr_der), &csr_length) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_base64url_encode(
            workspace->csr_der, csr_length, workspace->csr_base64url,
            sizeof(workspace->csr_base64url)) != PM3000_ACME_BASE64URL_OK ||
        pm3000_acme_build_finalize_payload(
            workspace->csr_base64url, workspace->payload,
            sizeof(workspace->payload), &payload_length) != PM3000_ACME_PROTOCOL_OK)
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    if (signed_post(&state, order.finalize_text, &order.finalize, state.kid,
                    (const unsigned char *)workspace->payload, payload_length,
                    &response) != PM3000_ACME_CLIENT_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (response.status_code != 200U && response.status_code != 202U)
        return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
    state.phase = PM3000_ACME_PHASE_FINALIZE;
    status = poll_order(&state, order_text, &order_url, 0, &order);
    if (status != PM3000_ACME_CLIENT_OK) return status;
    state.phase = PM3000_ACME_PHASE_CERTIFICATE_DOWNLOAD;
    if (signed_post(&state, order.certificate_text, &order.certificate,
                    state.kid, (const unsigned char *)"", 0U, &response) !=
            PM3000_ACME_CLIENT_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (response.status_code != 200U)
        return fail_http(&state, PM3000_ACME_CLIENT_PROTOCOL, &response);
    if (response.body_length == 0U ||
        response.body_length > PM3000_ACME_CERTIFICATE_MAX)
        return fail(&state, PM3000_ACME_CLIENT_PROTOCOL,
                    PM3000_ACME_REASON_PARSE);
    for (index = 0U; index < response.body_length; ++index)
        result->certificate_pem[index] = workspace->response_body[index];
    result->certificate_pem[response.body_length] = '\0';
    result->certificate_length = response.body_length;
    return PM3000_ACME_CLIENT_OK;
}
