#include "avtrans.h"
#include "identifiers.h"
#include "projector.h"
#include "token_admin.h"
#include "token_auth.h"

#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void cgi_headers(unsigned int status, const char *reason) {
    printf("Status: %u %s\r\nContent-Type: application/json\r\n"
           "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n\r\n",
           status, reason);
}

static int cgi_error(unsigned int status, const char *reason, const char *code,
                     const char *message) {
    cgi_headers(status, reason);
    printf("{\"code\":\"%s\",\"message\":\"%s\"}\n", code, message);
    return 0;
}

static const char *configured_path(const char *name, const char *production) {
#ifdef PM3000_TESTING
    const char *override = getenv(name);
    if (override != NULL && override[0] != '\0') return override;
#else
    (void)name;
#endif
    return production;
}

static int opaque_outlet_id(const char *value, char output[23]) {
    size_t index;
    for (index = 0; index < 22U; ++index) {
        unsigned char c = (unsigned char)value[index];
        if (c == '\0' || !((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
                            (c >= '0' && c <= '9') || c == '_' || c == '-')) return 0;
        output[index] = (char)c;
    }
    output[22] = '\0';
    return 1;
}

static int valid_token_path_id(const char *value) {
    char ignored[23];
    return strlen(value) == 26U && memcmp(value, "tok_", 4U) == 0 &&
           opaque_outlet_id(value + 4U, ignored);
}

struct json_cursor { const unsigned char *data; size_t length; size_t offset; };

static void json_space(struct json_cursor *cursor) {
    while (cursor->offset < cursor->length &&
           (cursor->data[cursor->offset] == ' ' || cursor->data[cursor->offset] == '\t' ||
            cursor->data[cursor->offset] == '\r' || cursor->data[cursor->offset] == '\n')) ++cursor->offset;
}

static int json_character(struct json_cursor *cursor, unsigned char expected) {
    json_space(cursor);
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != expected) return -1;
    return 0;
}

static int json_hex(unsigned char value) {
    if (value >= '0' && value <= '9') return value - '0';
    if (value >= 'a' && value <= 'f') return value - 'a' + 10;
    if (value >= 'A' && value <= 'F') return value - 'A' + 10;
    return -1;
}

/* Action members are deliberately ASCII-only; this also validates the complete string encoding. */
static int json_ascii_string(struct json_cursor *cursor, char *output, size_t capacity) {
    size_t used = 0U;
    if (cursor->offset >= cursor->length || cursor->data[cursor->offset++] != '"') return -1;
    while (cursor->offset < cursor->length) {
        unsigned char value = cursor->data[cursor->offset++];
        if (value == '"') { if (used >= capacity) return -1; output[used] = '\0'; return 0; }
        if (value < 0x20U || value >= 0x80U) return -1;
        if (value == '\\') {
            if (cursor->offset >= cursor->length) return -1;
            value = cursor->data[cursor->offset++];
            if (value == '"' || value == '\\' || value == '/') { }
            else if (value == 'b') value = '\b';
            else if (value == 'f') value = '\f';
            else if (value == 'n') value = '\n';
            else if (value == 'r') value = '\r';
            else if (value == 't') value = '\t';
            else if (value == 'u') {
                unsigned int codepoint = 0U; int index;
                for (index = 0; index < 4; ++index) { int part; if (cursor->offset >= cursor->length || (part = json_hex(cursor->data[cursor->offset++])) < 0) return -1; codepoint = codepoint * 16U + (unsigned int)part; }
                if (codepoint == 0U || codepoint >= 0x80U) return -1;
                value = (unsigned char)codepoint;
            } else return -1;
        }
        if (used + 1U >= capacity) return -1;
        output[used++] = (char)value;
    }
    return -1;
}

static int parse_action_request(const unsigned char *body, size_t length) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1, have_action = 0, have_revision = 0;
    if (length == 0U || json_character(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[32], value[32];
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') { ++cursor.offset; break; }
        if (!first && json_character(&cursor, ',') != 0) return -1;
        first = 0; json_space(&cursor);
        if (json_ascii_string(&cursor, key, sizeof(key)) != 0 || json_character(&cursor, ':') != 0) return -1;
        json_space(&cursor);
        if (json_ascii_string(&cursor, value, sizeof(value)) != 0) return -1;
        if (strcmp(key, "action") == 0) {
            if (have_action || (strcmp(value, "on") != 0 && strcmp(value, "off") != 0 && strcmp(value, "cycle") != 0)) return -1;
            have_action = 1;
        } else if (strcmp(key, "inventoryRevision") == 0) {
            char opaque[23]; if (have_revision || strlen(value) != 22U || !opaque_outlet_id(value, opaque)) return -1;
            have_revision = 1;
        } else return -1;
    }
    json_space(&cursor);
    return cursor.offset == cursor.length && have_action && have_revision ? 0 : -1;
}

static int ascii_equal_range(const char *value, size_t length, const char *literal) {
    size_t index;
    if (strlen(literal) != length) return 0;
    for (index = 0U; index < length; ++index) {
        unsigned char left = (unsigned char)value[index], right = (unsigned char)literal[index];
        if (left >= 'A' && left <= 'Z') left = (unsigned char)(left + ('a' - 'A'));
        if (right >= 'A' && right <= 'Z') right = (unsigned char)(right + ('a' - 'A'));
        if (left != right) return 0;
    }
    return 1;
}

/* RFC 9110 qvalue: 0 with up to three decimal digits, or 1 with only zero decimals. */
static int parse_quality(const char *value, const char *end, int *positive) {
    size_t decimals = 0U;
    while (value < end && (*value == ' ' || *value == '\t')) ++value;
    while (end > value && (end[-1] == ' ' || end[-1] == '\t')) --end;
    if (value >= end || (*value != '0' && *value != '1')) return -1;
    *positive = *value == '1';
    ++value;
    if (value < end) {
        if (*value++ != '.') return -1;
        while (value < end) {
            if (*value < '0' || *value > '9' || ++decimals > 3U) return -1;
            if (*value != '0') { if (*positive) return -1; *positive = 1; }
            ++value;
        }
    }
    return 0;
}

static int accepts_json(void) {
    const char *accept = getenv("HTTP_ACCEPT");
    int best_specificity = -1, best_positive = 0;
    if (accept == NULL || accept[0] == '\0') return 1;
    while (*accept != '\0') {
        const char *end = strchr(accept, ','); const char *semi; const char *finish, *cursor;
        size_t length; int quality_seen = 0, positive = 1, valid = 1, specificity = -1;
        if (end == NULL) end = accept + strlen(accept);
        while (accept < end && (*accept == ' ' || *accept == '\t')) ++accept;
        finish = end; while (finish > accept && (finish[-1] == ' ' || finish[-1] == '\t')) --finish;
        semi = memchr(accept, ';', (size_t)(finish - accept));
        length = (size_t)((semi == NULL ? finish : semi) - accept);
        while (length > 0U && (accept[length - 1U] == ' ' || accept[length - 1U] == '\t')) --length;
        if (ascii_equal_range(accept, length, "application/json")) specificity = 2;
        else if (ascii_equal_range(accept, length, "application/*")) specificity = 1;
        else if (ascii_equal_range(accept, length, "*/*")) specificity = 0;
        cursor = semi == NULL ? finish : semi;
        while (cursor < finish) {
            const char *parameter_end, *equals, *name_end;
            ++cursor;
            while (cursor < finish && (*cursor == ' ' || *cursor == '\t')) ++cursor;
            parameter_end = cursor; while (parameter_end < finish && *parameter_end != ';') ++parameter_end;
            equals = memchr(cursor, '=', (size_t)(parameter_end - cursor));
            name_end = equals == NULL ? parameter_end : equals;
            while (name_end > cursor && (name_end[-1] == ' ' || name_end[-1] == '\t')) --name_end;
            if (ascii_equal_range(cursor, (size_t)(name_end - cursor), "q")) {
                if (quality_seen || equals == NULL || parse_quality(equals + 1, parameter_end, &positive) != 0) valid = 0;
                quality_seen = 1;
            }
            cursor = parameter_end;
        }
        if (specificity >= 0 && valid) {
            if (specificity > best_specificity) {
                best_specificity = specificity;
                best_positive = positive;
            } else if (specificity == best_specificity && positive) best_positive = 1;
        }
        accept = *end == ',' ? end + 1 : end;
    }
    return best_specificity >= 0 && best_positive;
}

static int admin_bearer(const char *store_path, const char **token) {
    const char *header = getenv("HTTP_AUTHORIZATION");
    pm3000_authorization authorization;
    char error[160] = {0};
    int result;
    if (header == NULL || strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' ||
        strchr(header + 7U, ' ') != NULL) return 401;
    *token = header + 7U;
    result = pm3000_authorize(store_path, *token, "read", NULL,
                              &authorization, error, sizeof(error));
    if (result < 0) return 503;
    if (!authorization.authorized) return 401;
    result = pm3000_authorize(store_path, *token, "admin", NULL,
                              &authorization, error, sizeof(error));
    if (result < 0) return 503;
    return authorization.authorized ? 0 : 403;
}

static int admin_error(pm3000_token_result result) {
    if (result == PM3000_TOKEN_COMMITTED_UNCERTAIN)
        fputs("token mutation committed; directory durability uncertain\n", stderr);
    if (result == PM3000_TOKEN_AUTH)
        return cgi_error(403U, "Forbidden", "forbidden", "Administrator scope is required.");
    if (result == PM3000_TOKEN_BAD_REQUEST)
        return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
    if (result == PM3000_TOKEN_NOT_FOUND)
        return cgi_error(404U, "Not Found", "not_found", "Token not found.");
    if (result == PM3000_TOKEN_LAST_ADMIN)
        return cgi_error(409U, "Conflict", "last_administrator", "The final enabled administrator cannot be disabled or revoked.");
    if (result == PM3000_TOKEN_LIMIT)
        return cgi_error(409U, "Conflict", "token_limit_reached", "No additional tokens can be created.");
    return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Token administration is unavailable.");
}

static int read_json_body(unsigned char *body, size_t limit, size_t *body_length) {
    const char *content_type = getenv("CONTENT_TYPE");
    const char *content_encoding = getenv("HTTP_CONTENT_ENCODING");
    const char *length_text = getenv("CONTENT_LENGTH");
    char *end = NULL;
    unsigned long length;
    size_t used = 0U;
    if (content_encoding != NULL && content_encoding[0] != '\0') return 415;
    if (content_type == NULL || strcmp(content_type, "application/json") != 0) return 415;
    if (length_text == NULL || length_text[0] == '\0' || length_text[0] == '-' ||
        length_text[0] == '+') return 400;
    length = strtoul(length_text, &end, 10);
    if (end == length_text || *end != '\0') return 400;
    if (length > (unsigned long)limit) return 413;
    while (used < (size_t)length) {
        size_t amount = fread(body + used, 1U, (size_t)length - used, stdin);
        if (amount == 0U) return 400;
        used += amount;
    }
    *body_length = used;
    return 0;
}

static int deliver_created(const char *response, void *context) {
    (void)context;
    cgi_headers(201U, "Created");
    if (fputs(response, stdout) == EOF || fflush(stdout) != 0 || ferror(stdout)) return -1;
    return 0;
}

static int run_token_route(const char *method, const char *path, const char *store_path) {
    const char *token = NULL;
    int auth;
    pm3000_token_result result;
    char *response = NULL;
    if (strcmp(path, "/api/v1/tokens") == 0) {
        if (strcmp(method, "GET") != 0 && strcmp(method, "POST") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    } else if (strncmp(path, "/api/v1/tokens/", 15U) == 0 && strlen(path + 15U) >= 26U) {
        const char *suffix = path + 15U + 26U;
        char token_id[27]; memcpy(token_id, path + 15U, 26U); token_id[26] = '\0';
        if (valid_token_path_id(token_id) &&
            ((suffix[0] == '\0' && strcmp(method, "DELETE") != 0) ||
             ((strcmp(suffix, "/disable") == 0 || strcmp(suffix, "/enable") == 0) && strcmp(method, "POST") != 0)))
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    }
    auth = admin_bearer(store_path, &token);
    if (auth == 401) return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
    if (auth == 403) return cgi_error(403U, "Forbidden", "forbidden", "Administrator scope is required.");
    if (auth != 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Token administration is unavailable.");
    if (strcmp(path, "/api/v1/tokens") == 0) {
        if (strcmp(method, "GET") == 0) {
            result = pm3000_token_list(store_path, token, &response);
            if (result != PM3000_TOKEN_OK) return admin_error(result);
            cgi_headers(200U, "OK"); fputs(response, stdout); free(response);
            return ferror(stdout) ? 1 : 0;
        }
        if (strcmp(method, "POST") == 0) {
            unsigned char body[2049]; size_t length = 0U; int body_result = read_json_body(body, 2048U, &length);
            if (body_result == 415) return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type", "Content-Type must be application/json.");
            if (body_result == 413) return cgi_error(413U, "Payload Too Large", "payload_too_large", "The request body is too large.");
            if (body_result != 0) return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
            result = pm3000_token_create(store_path, token, body, length,
                                          deliver_created, NULL);
            if (result == PM3000_TOKEN_DELIVERY_ERROR ||
                result == PM3000_TOKEN_RESPONSE_SENT_ERROR ||
                result == PM3000_TOKEN_COMMITTED_UNCERTAIN) {
                if (result == PM3000_TOKEN_COMMITTED_UNCERTAIN)
                    fputs("token issuance committed; directory durability uncertain\n", stderr);
                return 1;
            }
            if (result != PM3000_TOKEN_OK) return admin_error(result);
            return 0;
        }
        return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    }
    {
        const char *identifier = path + 15U;
        char token_id[27];
        const char *suffix;
        if (strncmp(path, "/api/v1/tokens/", 15U) != 0 || strlen(identifier) < 26U) return cgi_error(404U, "Not Found", "not_found", "Route not found.");
        memcpy(token_id, identifier, 26U); token_id[26] = '\0'; suffix = identifier + 26U;
        if (!valid_token_path_id(token_id)) return cgi_error(404U, "Not Found", "not_found", "Token not found.");
        if (suffix[0] == '\0') {
            if (strcmp(method, "DELETE") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
            result = pm3000_token_revoke(store_path, token, token_id);
        } else if (strcmp(suffix, "/disable") == 0 || strcmp(suffix, "/enable") == 0) {
            if (strcmp(method, "POST") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
            result = pm3000_token_set_enabled(store_path, token, token_id, strcmp(suffix, "/enable") == 0);
        } else return cgi_error(404U, "Not Found", "not_found", "Route not found.");
        if (result != PM3000_TOKEN_OK) return admin_error(result);
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
    }
}

static int run_cgi(void) {
    const char *method = getenv("REQUEST_METHOD");
    const char *path = getenv("PATH_INFO");
    const char *https = getenv("HTTPS");
    const char *header;
    const char *token;
    pm3000_authorization authorization;
    unsigned char *response = NULL;
    size_t response_length = 0;
    char error[160] = {0};
    int auth_result;
    int detail_request = 0;
    char requested_outlet[23] = {0};
    if (https == NULL || strcmp(https, "on") != 0) {
        return cgi_error(403U, "Forbidden", "forbidden", "HTTPS is required.");
    }
    if (!accepts_json()) return cgi_error(406U, "Not Acceptable", "not_acceptable", "Only application/json is available.");
    if (method != NULL && path != NULL && strcmp(path, "/api/v1/health") == 0) {
        if (strcmp(method, "GET") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        cgi_headers(200U, "OK");
        fputs("{\"apiVersion\":\"v1\",\"status\":\"live\"}\n", stdout);
        return ferror(stdout) ? 1 : 0;
    }
    if (method != NULL && path != NULL &&
        (strcmp(path, "/api/v1/tokens") == 0 ||
         strncmp(path, "/api/v1/tokens/", 15U) == 0)) {
        return run_token_route(
            method, path,
            configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"));
    }
    if (method != NULL && path != NULL && strlen(path) == 46U &&
        memcmp(path, "/api/v1/outlets/", 16U) == 0 && memcmp(path + 38U, "/actions", 8U) == 0) {
        char outlet_id[23]; unsigned char body[1025]; size_t body_length = 0U; int body_result;
        if (!opaque_outlet_id(path + 16U, outlet_id)) return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        if (strcmp(method, "POST") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        body_result = read_json_body(body, 1024U, &body_length);
        if (body_result == 415) return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type", "Content-Type must be application/json without content encoding.");
        if (body_result == 413) return cgi_error(413U, "Payload Too Large", "payload_too_large", "The request body is too large.");
        if (body_result != 0 || parse_action_request(body, body_length) != 0)
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        header = getenv("HTTP_AUTHORIZATION");
        if (header == NULL || strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' || strchr(header + 7, ' ') != NULL) {
            return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
        }
        auth_result = pm3000_authorize(
            configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
            header + 7, "control", outlet_id, &authorization, error, sizeof(error));
        if (auth_result < 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
        if (!authorization.authenticated) return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
        if (!authorization.authorized) return cgi_error(403U, "Forbidden", "forbidden", "Token does not authorize this outlet action.");
        return cgi_error(503U, "Service Unavailable", "action_disabled", "Outlet actions are disabled.");
    }
    if (method == NULL || path == NULL) return cgi_error(404U, "Not Found", "not_found", "Route not found.");
    if (strcmp(path, "/api/v1/outlets") == 0) {
        if (strcmp(method, "GET") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    } else {
        if (strlen(path) != 38U || memcmp(path, "/api/v1/outlets/", 16U) != 0 ||
            !opaque_outlet_id(path + 16U, requested_outlet)) {
            return cgi_error(404U, "Not Found", "not_found", "Route not found.");
        }
        if (strcmp(method, "GET") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        detail_request = 1;
    }
    header = getenv("HTTP_AUTHORIZATION");
    if (header == NULL || strncmp(header, "Bearer ", 7U) != 0 || strchr(header + 7, ' ') != NULL) {
        return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
    }
    token = header + 7;
    auth_result = pm3000_authorize(
        configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
        token, "read", detail_request ? requested_outlet : NULL,
        &authorization, error, sizeof(error));
    if (auth_result < 0) {
        return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
    }
    if (!authorization.authenticated) {
        return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
    }
    if (!authorization.authorized) {
        return cgi_error(403U, "Forbidden", "forbidden", "Token does not authorize this outlet.");
    }
    if (pm3000_fetch_topology(
            configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
            configured_path("PM3000_CREDENTIALS", "/etc/pm3000-rest/controller.credentials"),
            &response, &response_length, error, sizeof(error)) != 0) {
        free(response);
        return cgi_error(503U, "Service Unavailable", "backend_unavailable", "Read-only backend unavailable.");
    }
    if (detail_request) {
        int projection = pm3000_project_detail_bytes(
            response, (unsigned long)response_length, requested_outlet, NULL, error, sizeof(error));
        if (projection == 1) {
            free(response);
            return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        }
        if (projection != 0) {
            free(response);
            return cgi_error(502U, "Bad Gateway", "backend_protocol_error", "Backend response rejected.");
        }
    } else if (pm3000_project_bytes_filtered(response, (unsigned long)response_length, NULL,
                                             authorization.unrestricted, &authorization.outlets[0][0],
                                             authorization.outlet_count, error, sizeof(error)) != 0) {
        free(response);
        return cgi_error(502U, "Bad Gateway", "backend_protocol_error", "Backend response rejected.");
    }
    cgi_headers(200U, "OK");
    if (detail_request) {
        if (pm3000_project_detail_bytes(response, (unsigned long)response_length,
                                        requested_outlet, stdout, error, sizeof(error)) != 0) {
            free(response); return 1;
        }
    } else if (pm3000_project_bytes_filtered(response, (unsigned long)response_length, stdout,
                                             authorization.unrestricted, &authorization.outlets[0][0],
                                             authorization.outlet_count, error, sizeof(error)) != 0) {
        free(response);
        return 1;
    }
    free(response);
    return ferror(stdout) ? 1 : 0;
}

static int derive(const char *kind, const char *identity) {
    char output[PM3000_ID_LENGTH + 1U];
    if (pm3000_derive_id(kind, identity, output) != 0) return 2;
    puts(output);
    return 0;
}

static int revision(int count, char **identities) {
    char output[PM3000_ID_LENGTH + 1U];
    if (pm3000_inventory_revision(identities, (size_t)count, output) != 0) return 2;
    puts(output);
    return 0;
}

int main(int argc, char **argv) {
    (void)signal(SIGPIPE, SIG_IGN);
    if (argc == 1) return run_cgi();
#ifdef PM3000_TESTING
    if ((argc == 5 || argc == 6) && strcmp(argv[1], "--authorize") == 0) {
        pm3000_authorization authorization;
        char error[160] = {0};
        int result = pm3000_authorize(argv[2], argv[3], argv[4], argc == 6 ? argv[5] : NULL,
                                      &authorization, error, sizeof(error));
        if (result < 0) { fprintf(stderr, "%s\n", error); return 3; }
        if (!authorization.authorized) return 4;
        fputs("{\"authorized\":true}\n", stdout);
        return 0;
    }
#endif
    if (argc == 4 && strcmp(argv[1], "--detail") == 0) {
        char error[160] = {0};
        int result = pm3000_project_detail_file(argv[2], argv[3], stdout, error, sizeof(error));
        if (result == 1) return 4;
        if (result != 0) { fprintf(stderr, "projection rejected: %s\n", error); return 3; }
        return 0;
    }
    if (argc == 4 && strcmp(argv[1], "--derive") == 0) {
        return derive(argv[2], argv[3]);
    }
    if (argc >= 3 && strcmp(argv[1], "--revision") == 0) {
        return revision(argc - 2, argv + 2);
    }
    if (argc == 3 && strcmp(argv[1], "--project") == 0) {
        char error[160] = {0};
        if (pm3000_project_file(argv[2], stdout, error, sizeof(error)) != 0) {
            fprintf(stderr, "projection rejected: %s\n", error);
            return 3;
        }
        return 0;
    }
    fputs("usage: pm3000-rest --derive outlet|pdu ID | --revision ID... | --project FILE\n", stderr);
    return 2;
}
