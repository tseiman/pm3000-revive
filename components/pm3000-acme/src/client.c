#include "pm3000_acme_client.h"
#include "pm3000_acme_base64url.h"
#include "pm3000_acme_challenge.h"
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
};

static void clear_result(struct pm3000_acme_client_result *result)
{
    result->account_url[0] = '\0';
    result->certificate_pem[0] = '\0';
    result->certificate_length = 0U;
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
    if (state->io->exchange(
            state->io->context, method, url, content_type, request_body,
            request_body_length, response, state->workspace->response_body,
            sizeof(state->workspace->response_body)) != 0)
        return PM3000_ACME_CLIENT_IO;
    if (response->body_length > PM3000_ACME_HTTP_BODY_MAX)
        return PM3000_ACME_CLIENT_PROTOCOL;
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
                sizeof(state->workspace->jws)) !=
            PM3000_ACME_JWS_OK) return PM3000_ACME_CLIENT_PROTOCOL;
        if (exchange(state, "POST", target, "application/jose+json",
                     (const unsigned char *)state->workspace->jws,
                     text_length(state->workspace->jws),
                     response) != PM3000_ACME_CLIENT_OK)
            return PM3000_ACME_CLIENT_IO;
        if (response->replay_nonce[0] == '\0' ||
            !copy_text(state->nonce, sizeof(state->nonce),
                       response->replay_nonce))
            return PM3000_ACME_CLIENT_PROTOCOL;
        if (response->status_code == 400U && attempt == 0U &&
            pm3000_acme_error_is_bad_nonce(
                state->workspace->response_body, response->body_length))
            continue;
        return PM3000_ACME_CLIENT_OK;
    }
    return PM3000_ACME_CLIENT_REJECTED;
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
    if (!parse_same_origin_url(state, url_text, &url)) return result;
    if (signed_post(state, url_text, &url, state->kid,
                    (const unsigned char *)"", 0U, &response) !=
            PM3000_ACME_CLIENT_OK || response.status_code != 200U ||
        pm3000_acme_authorization_parse(
            state->workspace->response_body, response.body_length,
            &state->origin, &authorization) != PM3000_ACME_PROTOCOL_OK ||
        !configured_identifier(state, authorization.identifier,
                               identifier_index))
        return result;
    if (authorization.status == PM3000_ACME_STATUS_VALID)
        return PM3000_ACME_CLIENT_OK;
    if (authorization.status != PM3000_ACME_STATUS_PENDING ||
        pm3000_acme_challenge_publish(
            state->config->challenge_webroot, authorization.challenge.token,
            state->thumbprint) != PM3000_ACME_CHALLENGE_OK)
        return result;
    published = 1;
    if (!copy_text(published_token, sizeof(published_token),
                   authorization.challenge.token)) goto cleanup;
    if (signed_post(state, authorization.challenge.url_text,
                    &authorization.challenge.url, state->kid,
                    (const unsigned char *)"{}", 2U, &response) !=
            PM3000_ACME_CLIENT_OK ||
        (response.status_code != 200U && response.status_code != 202U))
        goto cleanup;
    for (attempt = 0U; attempt < state->config->poll_attempts; ++attempt) {
        if (state->io->sleep(state->io->context, 1U) != 0) {
            result = PM3000_ACME_CLIENT_IO;
            goto cleanup;
        }
        if (signed_post(state, url_text, &url, state->kid,
                        (const unsigned char *)"", 0U, &response) !=
                PM3000_ACME_CLIENT_OK || response.status_code != 200U ||
            pm3000_acme_authorization_parse(
                state->workspace->response_body, response.body_length,
                &state->origin, &authorization) != PM3000_ACME_PROTOCOL_OK)
            goto cleanup;
        if (authorization.status == PM3000_ACME_STATUS_VALID) {
            result = PM3000_ACME_CLIENT_OK;
            goto cleanup;
        }
        if (authorization.status != PM3000_ACME_STATUS_PENDING &&
            authorization.status != PM3000_ACME_STATUS_PROCESSING) {
            result = PM3000_ACME_CLIENT_REJECTED;
            goto cleanup;
        }
    }
    result = PM3000_ACME_CLIENT_TIMEOUT;
cleanup:
    if (published && pm3000_acme_challenge_remove(
            state->config->challenge_webroot, published_token) !=
            PM3000_ACME_CHALLENGE_OK && result == PM3000_ACME_CLIENT_OK)
        result = PM3000_ACME_CLIENT_IO;
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
            return PM3000_ACME_CLIENT_IO;
        if (signed_post(state, order_text, order_url, state->kid,
                        (const unsigned char *)"", 0U, &response) !=
                PM3000_ACME_CLIENT_OK || response.status_code != 200U ||
            pm3000_acme_order_parse(state->workspace->response_body,
                                    response.body_length, &state->origin,
                                    order) != PM3000_ACME_PROTOCOL_OK)
            return PM3000_ACME_CLIENT_PROTOCOL;
        if (before_finalize && order->status == PM3000_ACME_STATUS_READY)
            return PM3000_ACME_CLIENT_OK;
        if (!before_finalize && order->status == PM3000_ACME_STATUS_VALID &&
            order->have_certificate)
            return PM3000_ACME_CLIENT_OK;
        if (order->status == PM3000_ACME_STATUS_INVALID)
            return PM3000_ACME_CLIENT_REJECTED;
        if (order->status != PM3000_ACME_STATUS_PENDING &&
            order->status != PM3000_ACME_STATUS_PROCESSING &&
            !(before_finalize && order->status == PM3000_ACME_STATUS_VALID))
            return PM3000_ACME_CLIENT_PROTOCOL;
    }
    return PM3000_ACME_CLIENT_TIMEOUT;
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
    state.nonce[0] = '\0';
    state.kid[0] = '\0';
    if (pm3000_acme_url_parse(config->directory_url, &state.origin) !=
            PM3000_ACME_URL_OK ||
        pm3000_acme_crypto_thumbprint(
            config->account_key, state.thumbprint,
            sizeof(state.thumbprint)) != PM3000_ACME_CRYPTO_OK)
        return PM3000_ACME_CLIENT_INVALID;

    if (exchange(&state, "GET", &state.origin, (const char *)0,
                 (const unsigned char *)0, 0U, &response) !=
            PM3000_ACME_CLIENT_OK || response.status_code != 200U ||
        pm3000_acme_directory_parse(workspace->response_body,
                                    response.body_length, &state.origin,
                                    &state.directory) !=
            PM3000_ACME_PROTOCOL_OK)
        return PM3000_ACME_CLIENT_PROTOCOL;
    if (exchange(&state, "HEAD", &state.directory.new_nonce,
                 (const char *)0, (const unsigned char *)0, 0U, &response) !=
            PM3000_ACME_CLIENT_OK ||
        (response.status_code != 200U && response.status_code != 204U) ||
        response.replay_nonce[0] == '\0' ||
        !copy_text(state.nonce, sizeof(state.nonce), response.replay_nonce))
        return PM3000_ACME_CLIENT_PROTOCOL;

    if (signed_post(&state, state.directory.new_account_text,
                    &state.directory.new_account, (const char *)0,
                    (const unsigned char *)
                        "{\"termsOfServiceAgreed\":true}",
                    29U, &response) != PM3000_ACME_CLIENT_OK ||
        (response.status_code != 200U && response.status_code != 201U) ||
        response.location[0] == '\0' ||
        pm3000_acme_account_parse(workspace->response_body,
                                  response.body_length) !=
            PM3000_ACME_PROTOCOL_OK ||
        !copy_text(state.kid, sizeof(state.kid), response.location) ||
        !parse_same_origin_url(&state, state.kid, &order_url) ||
        !copy_text(result->account_url, sizeof(result->account_url), state.kid))
        return PM3000_ACME_CLIENT_PROTOCOL;

    if (pm3000_acme_build_order_payload(
            config->dns_names, config->dns_name_count, workspace->payload,
            sizeof(workspace->payload), &payload_length) !=
            PM3000_ACME_PROTOCOL_OK ||
        signed_post(&state, state.directory.new_order_text,
                    &state.directory.new_order, state.kid,
                    (const unsigned char *)workspace->payload, payload_length,
                    &response) != PM3000_ACME_CLIENT_OK ||
        (response.status_code != 200U && response.status_code != 201U) ||
        !parse_same_origin_url(&state, response.location, &order_url) ||
        !copy_text(order_text, sizeof(order_text), response.location) ||
        pm3000_acme_order_parse(workspace->response_body,
                                response.body_length, &state.origin, &order) !=
            PM3000_ACME_PROTOCOL_OK ||
        order.authorization_count != config->dns_name_count)
        return PM3000_ACME_CLIENT_PROTOCOL;
    for (index = 0U; index < PM3000_ACME_MAX_IDENTIFIERS; ++index)
        matched[index] = 0U;
    for (index = 0U; index < order.authorization_count; ++index) {
        status = authorize_one(&state, order.authorization_text[index],
                               &identifier_index);
        if (status != PM3000_ACME_CLIENT_OK) return status;
        if (identifier_index >= config->dns_name_count || matched[identifier_index])
            return PM3000_ACME_CLIENT_PROTOCOL;
        matched[identifier_index] = 1U;
    }

    status = poll_order(&state, order_text, &order_url, 1, &order);
    if (status != PM3000_ACME_CLIENT_OK) return status;
    if (pm3000_acme_crypto_csr_der(
            config->certificate_key, config->dns_names,
            config->dns_name_count, workspace->csr_der,
            sizeof(workspace->csr_der), &csr_length) != PM3000_ACME_CRYPTO_OK ||
        pm3000_acme_base64url_encode(
            workspace->csr_der, csr_length, workspace->csr_base64url,
            sizeof(workspace->csr_base64url)) !=
            PM3000_ACME_BASE64URL_OK ||
        pm3000_acme_build_finalize_payload(
            workspace->csr_base64url, workspace->payload,
            sizeof(workspace->payload), &payload_length) !=
            PM3000_ACME_PROTOCOL_OK ||
        signed_post(&state, order.finalize_text, &order.finalize, state.kid,
                    (const unsigned char *)workspace->payload, payload_length,
                    &response) != PM3000_ACME_CLIENT_OK ||
        (response.status_code != 200U && response.status_code != 202U))
        return PM3000_ACME_CLIENT_PROTOCOL;
    status = poll_order(&state, order_text, &order_url, 0, &order);
    if (status != PM3000_ACME_CLIENT_OK) return status;
    if (signed_post(&state, order.certificate_text, &order.certificate,
                    state.kid, (const unsigned char *)"", 0U, &response) !=
            PM3000_ACME_CLIENT_OK || response.status_code != 200U ||
        response.body_length == 0U ||
        response.body_length > PM3000_ACME_CERTIFICATE_MAX)
        return PM3000_ACME_CLIENT_PROTOCOL;
    for (index = 0U; index < response.body_length; ++index)
        result->certificate_pem[index] = workspace->response_body[index];
    result->certificate_pem[response.body_length] = '\0';
    result->certificate_length = response.body_length;
    return PM3000_ACME_CLIENT_OK;
}
