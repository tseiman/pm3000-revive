#include "pm3000_acme_protocol.h"
#include "pm3000_acme_json.h"

static void clear_url(struct pm3000_acme_url *url)
{
    url->host[0] = '\0';
    url->port = 0U;
    url->path[0] = '\0';
}

static void clear_directory(struct pm3000_acme_directory *directory)
{
    directory->new_nonce_text[0] = '\0';
    directory->new_account_text[0] = '\0';
    directory->new_order_text[0] = '\0';
    clear_url(&directory->new_nonce);
    clear_url(&directory->new_account);
    clear_url(&directory->new_order);
}

static int read_endpoint(const struct pm3000_acme_json_document *document,
                         int object_token, const char *name,
                         const struct pm3000_acme_url *origin,
                         char *text, unsigned int text_capacity,
                         struct pm3000_acme_url *url)
{
    int token;
    if (pm3000_acme_json_object_get(document, object_token, name, &token) !=
            PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(document, token, text, text_capacity) !=
            PM3000_ACME_JSON_OK ||
        pm3000_acme_url_parse(text, url) != PM3000_ACME_URL_OK ||
        !pm3000_acme_url_same_origin(origin, url)) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

int pm3000_acme_directory_parse(const unsigned char *json,
                                unsigned int json_length,
                                const struct pm3000_acme_url *origin,
                                struct pm3000_acme_directory *directory)
{
    struct pm3000_acme_json_document document;
    int result;
    if (origin == (const struct pm3000_acme_url *)0 ||
        directory == (struct pm3000_acme_directory *)0) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    clear_directory(directory);
    result = pm3000_acme_json_parse(json, json_length, &document);
    if (result != PM3000_ACME_JSON_OK) {
        return result == PM3000_ACME_JSON_LIMIT ? PM3000_ACME_PROTOCOL_LIMIT :
                                                 PM3000_ACME_PROTOCOL_INVALID;
    }
    if (document.token_count == 0U ||
        document.tokens[0].type != PM3000_ACME_JSON_OBJECT ||
        read_endpoint(&document, 0, "newNonce", origin,
                      directory->new_nonce_text,
                      sizeof(directory->new_nonce_text),
                      &directory->new_nonce) != PM3000_ACME_PROTOCOL_OK ||
        read_endpoint(&document, 0, "newAccount", origin,
                      directory->new_account_text,
                      sizeof(directory->new_account_text),
                      &directory->new_account) != PM3000_ACME_PROTOCOL_OK ||
        read_endpoint(&document, 0, "newOrder", origin,
                      directory->new_order_text,
                      sizeof(directory->new_order_text),
                      &directory->new_order) != PM3000_ACME_PROTOCOL_OK) {
        clear_directory(directory);
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
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

static int read_string(const struct pm3000_acme_json_document *document,
                       int object_token, const char *name,
                       char *output, unsigned int capacity)
{
    int value_token;
    if (pm3000_acme_json_object_get(document, object_token, name,
                                    &value_token) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_string_copy(document, value_token, output, capacity) !=
            PM3000_ACME_JSON_OK) {
        if (capacity > 0U) output[0] = '\0';
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

static enum pm3000_acme_status status_value(const char *text)
{
    if (text_equal(text, "pending")) return PM3000_ACME_STATUS_PENDING;
    if (text_equal(text, "ready")) return PM3000_ACME_STATUS_READY;
    if (text_equal(text, "processing")) return PM3000_ACME_STATUS_PROCESSING;
    if (text_equal(text, "valid")) return PM3000_ACME_STATUS_VALID;
    if (text_equal(text, "invalid")) return PM3000_ACME_STATUS_INVALID;
    if (text_equal(text, "deactivated")) return PM3000_ACME_STATUS_DEACTIVATED;
    if (text_equal(text, "expired")) return PM3000_ACME_STATUS_EXPIRED;
    if (text_equal(text, "revoked")) return PM3000_ACME_STATUS_REVOKED;
    return PM3000_ACME_STATUS_NONE;
}

static enum pm3000_acme_status read_status(
    const struct pm3000_acme_json_document *document, int object_token)
{
    char text[16];
    if (read_string(document, object_token, "status", text, sizeof(text)) !=
        PM3000_ACME_PROTOCOL_OK) return PM3000_ACME_STATUS_NONE;
    return status_value(text);
}

static int order_status_allowed(enum pm3000_acme_status status)
{
    return status == PM3000_ACME_STATUS_PENDING ||
           status == PM3000_ACME_STATUS_READY ||
           status == PM3000_ACME_STATUS_PROCESSING ||
           status == PM3000_ACME_STATUS_VALID ||
           status == PM3000_ACME_STATUS_INVALID;
}

static int authorization_status_allowed(enum pm3000_acme_status status)
{
    return status == PM3000_ACME_STATUS_PENDING ||
           status == PM3000_ACME_STATUS_VALID ||
           status == PM3000_ACME_STATUS_INVALID ||
           status == PM3000_ACME_STATUS_DEACTIVATED ||
           status == PM3000_ACME_STATUS_EXPIRED ||
           status == PM3000_ACME_STATUS_REVOKED;
}

static int challenge_status_allowed(enum pm3000_acme_status status)
{
    return status == PM3000_ACME_STATUS_PENDING ||
           status == PM3000_ACME_STATUS_PROCESSING ||
           status == PM3000_ACME_STATUS_VALID ||
           status == PM3000_ACME_STATUS_INVALID;
}

static int parse_document(const unsigned char *json, unsigned int json_length,
                          struct pm3000_acme_json_document *document)
{
    int result = pm3000_acme_json_parse(json, json_length, document);
    if (result != PM3000_ACME_JSON_OK) {
        return result == PM3000_ACME_JSON_LIMIT ? PM3000_ACME_PROTOCOL_LIMIT :
                                                 PM3000_ACME_PROTOCOL_INVALID;
    }
    if (document->token_count == 0U ||
        document->tokens[0].type != PM3000_ACME_JSON_OBJECT) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

static void clear_order(struct pm3000_acme_order *order)
{
    unsigned int index;
    order->status = PM3000_ACME_STATUS_NONE;
    order->authorization_count = 0U;
    for (index = 0U; index < PM3000_ACME_MAX_IDENTIFIERS; ++index)
        order->authorization_text[index][0] = '\0';
    order->finalize_text[0] = '\0';
    clear_url(&order->finalize);
    order->have_certificate = 0;
    order->certificate_text[0] = '\0';
    clear_url(&order->certificate);
}

int pm3000_acme_order_parse(const unsigned char *json,
                            unsigned int json_length,
                            const struct pm3000_acme_url *origin,
                            struct pm3000_acme_order *order)
{
    struct pm3000_acme_json_document document;
    int authorizations_token;
    int certificate_token;
    unsigned int count;
    unsigned int index;
    int result;
    if (origin == (const struct pm3000_acme_url *)0 ||
        order == (struct pm3000_acme_order *)0) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    clear_order(order);
    result = parse_document(json, json_length, &document);
    if (result != PM3000_ACME_PROTOCOL_OK) return result;
    order->status = read_status(&document, 0);
    if (!order_status_allowed(order->status) ||
        pm3000_acme_json_object_get(&document, 0, "authorizations",
                                    &authorizations_token) !=
            PM3000_ACME_JSON_OK ||
        pm3000_acme_json_array_length(&document, authorizations_token, &count) !=
            PM3000_ACME_JSON_OK ||
        count == 0U || count > PM3000_ACME_MAX_IDENTIFIERS ||
        read_endpoint(&document, 0, "finalize", origin, order->finalize_text,
                      sizeof(order->finalize_text), &order->finalize) !=
            PM3000_ACME_PROTOCOL_OK) {
        clear_order(order);
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    for (index = 0U; index < count; ++index) {
        int value_token;
        struct pm3000_acme_url parsed;
        if (pm3000_acme_json_array_get(&document, authorizations_token, index,
                                       &value_token) != PM3000_ACME_JSON_OK ||
            pm3000_acme_json_string_copy(
                &document, value_token, order->authorization_text[index],
                sizeof(order->authorization_text[index])) !=
                PM3000_ACME_JSON_OK ||
            pm3000_acme_url_parse(order->authorization_text[index], &parsed) !=
                PM3000_ACME_URL_OK ||
            !pm3000_acme_url_same_origin(origin, &parsed)) {
            clear_order(order);
            return PM3000_ACME_PROTOCOL_INVALID;
        }
    }
    order->authorization_count = count;
    result = pm3000_acme_json_object_get(&document, 0, "certificate",
                                         &certificate_token);
    if (result == PM3000_ACME_JSON_OK) {
        if (pm3000_acme_json_string_copy(
                &document, certificate_token, order->certificate_text,
                sizeof(order->certificate_text)) != PM3000_ACME_JSON_OK ||
            pm3000_acme_url_parse(order->certificate_text,
                                  &order->certificate) != PM3000_ACME_URL_OK ||
            !pm3000_acme_url_same_origin(origin, &order->certificate)) {
            clear_order(order);
            return PM3000_ACME_PROTOCOL_INVALID;
        }
        order->have_certificate = 1;
    } else if (result != PM3000_ACME_JSON_NOT_FOUND) {
        clear_order(order);
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    if (order->status == PM3000_ACME_STATUS_VALID &&
        !order->have_certificate) {
        clear_order(order);
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

static void clear_authorization(struct pm3000_acme_authorization *authorization)
{
    authorization->status = PM3000_ACME_STATUS_NONE;
    authorization->identifier[0] = '\0';
    authorization->challenge.status = PM3000_ACME_STATUS_NONE;
    authorization->challenge.token[0] = '\0';
    authorization->challenge.url_text[0] = '\0';
    clear_url(&authorization->challenge.url);
}

static int token_is_valid(const char *token)
{
    unsigned int length = 0U;
    while (token[length] != '\0') {
        char value = token[length];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_')) {
            return 0;
        }
        if (++length > PM3000_ACME_TOKEN_MAX) return 0;
    }
    return length != 0U;
}

int pm3000_acme_authorization_parse(
    const unsigned char *json, unsigned int json_length,
    const struct pm3000_acme_url *origin,
    struct pm3000_acme_authorization *authorization)
{
    struct pm3000_acme_json_document document;
    int identifier_token;
    int wildcard_token;
    int challenges_token;
    unsigned int challenge_count;
    unsigned int index;
    int found_http = 0;
    int result;
    char type[16];
    char identifier[PM3000_ACME_HOST_MAX + 1U];
    if (origin == (const struct pm3000_acme_url *)0 ||
        authorization == (struct pm3000_acme_authorization *)0) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    clear_authorization(authorization);
    result = parse_document(json, json_length, &document);
    if (result != PM3000_ACME_PROTOCOL_OK) return result;
    authorization->status = read_status(&document, 0);
    if (!authorization_status_allowed(authorization->status)) goto rejected;
    result = pm3000_acme_json_object_get(&document, 0, "wildcard",
                                         &wildcard_token);
    if (result == PM3000_ACME_JSON_OK) {
        if (document.tokens[wildcard_token].type != PM3000_ACME_JSON_FALSE)
            goto rejected;
    } else if (result != PM3000_ACME_JSON_NOT_FOUND) {
        goto rejected;
    }
    if (pm3000_acme_json_object_get(&document, 0, "identifier",
                                    &identifier_token) != PM3000_ACME_JSON_OK ||
        document.tokens[identifier_token].type != PM3000_ACME_JSON_OBJECT ||
        read_string(&document, identifier_token, "type", type,
                    sizeof(type)) != PM3000_ACME_PROTOCOL_OK ||
        !text_equal(type, "dns") ||
        read_string(&document, identifier_token, "value", identifier,
                    sizeof(identifier)) != PM3000_ACME_PROTOCOL_OK ||
        pm3000_acme_dns_name_normalize(
            identifier, authorization->identifier,
            sizeof(authorization->identifier)) != PM3000_ACME_URL_OK ||
        pm3000_acme_json_object_get(&document, 0, "challenges",
                                    &challenges_token) != PM3000_ACME_JSON_OK ||
        pm3000_acme_json_array_length(&document, challenges_token,
                                      &challenge_count) != PM3000_ACME_JSON_OK ||
        challenge_count == 0U ||
        challenge_count > PM3000_ACME_JSON_MAX_MEMBERS) {
        goto rejected;
    }
    for (index = 0U; index < challenge_count; ++index) {
        int challenge_token;
        if (pm3000_acme_json_array_get(&document, challenges_token, index,
                                       &challenge_token) != PM3000_ACME_JSON_OK ||
            document.tokens[challenge_token].type != PM3000_ACME_JSON_OBJECT ||
            read_string(&document, challenge_token, "type", type,
                        sizeof(type)) != PM3000_ACME_PROTOCOL_OK) {
            goto rejected;
        }
        if (!text_equal(type, "http-01")) continue;
        if (found_http) goto rejected;
        found_http = 1;
        authorization->challenge.status = read_status(&document, challenge_token);
        if (!challenge_status_allowed(authorization->challenge.status) ||
            read_string(&document, challenge_token, "token",
                        authorization->challenge.token,
                        sizeof(authorization->challenge.token)) !=
                PM3000_ACME_PROTOCOL_OK ||
            !token_is_valid(authorization->challenge.token) ||
            read_endpoint(&document, challenge_token, "url", origin,
                          authorization->challenge.url_text,
                          sizeof(authorization->challenge.url_text),
                          &authorization->challenge.url) !=
                PM3000_ACME_PROTOCOL_OK) {
            goto rejected;
        }
    }
    if (!found_http) goto rejected;
    return PM3000_ACME_PROTOCOL_OK;

rejected:
    clear_authorization(authorization);
    return PM3000_ACME_PROTOCOL_INVALID;
}

int pm3000_acme_account_parse(const unsigned char *json,
                              unsigned int json_length)
{
    struct pm3000_acme_json_document document;
    if (pm3000_acme_json_parse(json, json_length, &document) !=
            PM3000_ACME_JSON_OK ||
        document.tokens[0].type != PM3000_ACME_JSON_OBJECT ||
        read_status(&document, 0) != PM3000_ACME_STATUS_VALID) {
        return PM3000_ACME_PROTOCOL_INVALID;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

int pm3000_acme_error_is_bad_nonce(const unsigned char *json,
                                   unsigned int json_length)
{
    struct pm3000_acme_json_document document;
    char type[64];
    if (pm3000_acme_json_parse(json, json_length, &document) !=
            PM3000_ACME_JSON_OK ||
        document.tokens[0].type != PM3000_ACME_JSON_OBJECT ||
        read_string(&document, 0, "type", type, sizeof(type)) !=
            PM3000_ACME_PROTOCOL_OK) return 0;
    return text_equal(type, "urn:ietf:params:acme:error:badNonce");
}

static int payload_append_char(char *output, unsigned int capacity,
                               unsigned int *used, char value)
{
    if (*used + 1U >= capacity) return PM3000_ACME_PROTOCOL_LIMIT;
    output[(*used)++] = value;
    output[*used] = '\0';
    return PM3000_ACME_PROTOCOL_OK;
}

static int payload_append_text(char *output, unsigned int capacity,
                               unsigned int *used, const char *text)
{
    unsigned int index = 0U;
    while (text[index] != '\0') {
        if (payload_append_char(output, capacity, used, text[index]) !=
            PM3000_ACME_PROTOCOL_OK) return PM3000_ACME_PROTOCOL_LIMIT;
        ++index;
    }
    return PM3000_ACME_PROTOCOL_OK;
}

int pm3000_acme_build_order_payload(
    const char *const *dns_names, unsigned int dns_name_count,
    char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    char normalized[PM3000_ACME_MAX_IDENTIFIERS]
                   [PM3000_ACME_HOST_MAX + 1U];
    unsigned int used = 0U;
    unsigned int index;
    unsigned int previous;
    if (output_length != (unsigned int *)0) *output_length = 0U;
    if (dns_names == (const char *const *)0 || output == (char *)0 ||
        output_capacity == 0U || output_length == (unsigned int *)0 ||
        dns_name_count == 0U || dns_name_count > PM3000_ACME_MAX_IDENTIFIERS)
        return PM3000_ACME_PROTOCOL_INVALID;
    output[0] = '\0';
    if (payload_append_text(output, output_capacity, &used,
                            "{\"identifiers\":[") !=
        PM3000_ACME_PROTOCOL_OK) return PM3000_ACME_PROTOCOL_LIMIT;
    for (index = 0U; index < dns_name_count; ++index) {
        if (pm3000_acme_dns_name_normalize(
                dns_names[index], normalized[index],
                sizeof(normalized[index])) != PM3000_ACME_URL_OK)
            return PM3000_ACME_PROTOCOL_INVALID;
        for (previous = 0U; previous < index; ++previous)
            if (text_equal(normalized[index], normalized[previous]))
                return PM3000_ACME_PROTOCOL_INVALID;
        if (index != 0U && payload_append_char(
                output, output_capacity, &used, ',') != PM3000_ACME_PROTOCOL_OK)
            return PM3000_ACME_PROTOCOL_LIMIT;
        if (payload_append_text(
                output, output_capacity, &used,
                "{\"type\":\"dns\",\"value\":\"") !=
                PM3000_ACME_PROTOCOL_OK ||
            payload_append_text(output, output_capacity, &used,
                                normalized[index]) !=
                PM3000_ACME_PROTOCOL_OK ||
            payload_append_text(output, output_capacity, &used, "\"}") !=
                PM3000_ACME_PROTOCOL_OK)
            return PM3000_ACME_PROTOCOL_LIMIT;
    }
    if (payload_append_text(output, output_capacity, &used, "]}") !=
        PM3000_ACME_PROTOCOL_OK) return PM3000_ACME_PROTOCOL_LIMIT;
    *output_length = used;
    return PM3000_ACME_PROTOCOL_OK;
}

static int base64url_value(const char *text, unsigned int maximum)
{
    unsigned int index = 0U;
    if (text == (const char *)0) return 0;
    while (text[index] != '\0') {
        char value = text[index];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_'))
            return 0;
        if (++index > maximum) return 0;
    }
    return index != 0U;
}

int pm3000_acme_build_finalize_payload(
    const char *csr_base64url, char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    unsigned int used = 0U;
    if (output_length != (unsigned int *)0) *output_length = 0U;
    if (output == (char *)0 || output_capacity == 0U ||
        output_length == (unsigned int *)0 ||
        !base64url_value(csr_base64url, 6000U))
        return PM3000_ACME_PROTOCOL_INVALID;
    output[0] = '\0';
    if (payload_append_text(output, output_capacity, &used, "{\"csr\":\"") !=
            PM3000_ACME_PROTOCOL_OK ||
        payload_append_text(output, output_capacity, &used, csr_base64url) !=
            PM3000_ACME_PROTOCOL_OK ||
        payload_append_text(output, output_capacity, &used, "\"}") !=
            PM3000_ACME_PROTOCOL_OK)
        return PM3000_ACME_PROTOCOL_LIMIT;
    *output_length = used;
    return PM3000_ACME_PROTOCOL_OK;
}
