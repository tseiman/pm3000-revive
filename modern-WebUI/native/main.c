#define _GNU_SOURCE

#include "avtrans.h"
#include "controller_xml.h"
#include "fixed_form.h"
#include "identifiers.h"
#include "projector.h"
#include "service_session.h"
#include "session.h"
#include "token_admin.h"
#include "token_auth.h"

#include <signal.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

static void cgi_headers_extra(unsigned int status, const char *reason,
                              const char *cookie) {
    printf("Status: %u %s\r\nContent-Type: application/json\r\n"
           "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n",
           status, reason);
    if (cookie != NULL) printf("Set-Cookie: %s\r\n", cookie);
    fputs("\r\n", stdout);
}

static void cgi_headers(unsigned int status, const char *reason) {
    cgi_headers_extra(status, reason, NULL);
}

static void cgi_settings_headers(const char *etag) {
    printf("Status: 200 OK\r\nContent-Type: application/json\r\n"
           "Cache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\n"
           "ETag: %s\r\n\r\n", etag);
}

static int cgi_error_extra(unsigned int status, const char *reason, const char *code,
                           const char *message, const char *cookie) {
    cgi_headers_extra(status, reason, cookie);
    printf("{\"code\":\"%s\",\"message\":\"%s\"}\n", code, message);
    return 0;
}

static int cgi_error(unsigned int status, const char *reason, const char *code,
                     const char *message) {
    return cgi_error_extra(status, reason, code, message, NULL);
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

static const char *service_helper_path(void) {
    return configured_path(
        "PM3000_SERVICE_SESSION_HELPER",
        "/mnt/hdUser/pm3000-revive/webui/current/bin/pm3000-gsp-session-helper");
}

static int service_fetch_topology(const char *socket_path,
                                  unsigned char **response,
                                  size_t *response_length,
                                  char *error, unsigned int error_size) {
    struct pm3000_service_session session;
    int result = pm3000_service_session_open(service_helper_path(), &session,
                                              error, error_size);
    if (result != 0) return -1;
    result = pm3000_fetch_topology_session(socket_path, session.sid, response,
                                           response_length, error, error_size);
    if (pm3000_service_session_close(&session) != 0 && result == 0) {
        (void)snprintf(error, error_size, "%s", "service session cleanup failed");
        result = -1;
    }
    return result;
}

static int service_fetch_pdus(const char *socket_path,
                              unsigned char **response,
                              size_t *response_length,
                              char *error, unsigned int error_size) {
    struct pm3000_service_session session;
    int result = pm3000_service_session_open(service_helper_path(), &session,
                                              error, error_size);
    if (result != 0) return -1;
    result = pm3000_fetch_pdus_session(socket_path, session.sid, response,
                                       response_length, error, error_size);
    if (pm3000_service_session_close(&session) != 0 && result == 0) {
        (void)snprintf(error, error_size, "%s", "service session cleanup failed");
        result = -1;
    }
    return result;
}

static int service_resolve_outlet_selector(const char *socket_path,
                                           const char *selector,
                                           const char *revision,
                                           char outlet_id[23],
                                           char *error, unsigned int error_size) {
    unsigned char *topology = NULL;
    size_t topology_length = 0U;
    char identity[256];
    int result = service_fetch_topology(socket_path, &topology, &topology_length,
                                        error, error_size);
    if (result == 0)
        result = pm3000_resolve_outlet_selector(
            topology, (unsigned long)topology_length, selector, revision,
            outlet_id, identity, sizeof(identity), error, error_size);
    free(topology);
    memset(identity, 0, sizeof(identity));
    return result;
}

static int service_apply_outlet_action(const char *socket_path,
                                       const char *outlet_id,
                                       const char *revision,
                                       const char *action,
                                       char *error, unsigned int error_size) {
    struct pm3000_service_session session;
    int result = pm3000_service_session_open(service_helper_path(), &session,
                                              error, error_size);
    if (result != 0) return -1;
    result = pm3000_apply_outlet_action_session(
        socket_path, session.sid, outlet_id, revision, action, error, error_size);
    if (pm3000_service_session_close(&session) != 0 && result == 0) {
        (void)snprintf(error, error_size, "%s", "service session cleanup outcome unknown");
        result = 3;
    }
    return result;
}

static int service_apply_pdu_action(const char *socket_path,
                                    const char *pdu_id,
                                    const char *revision,
                                    const char *action,
                                    char *error, unsigned int error_size) {
    struct pm3000_service_session session;
    int result = pm3000_service_session_open(service_helper_path(), &session,
                                              error, error_size);
    if (result != 0) return -1;
    result = pm3000_apply_pdu_action_session(
        socket_path, session.sid, pdu_id, revision, action, error, error_size);
    if (pm3000_service_session_close(&session) != 0 && result == 0) {
        (void)snprintf(error, error_size, "%s", "service session cleanup outcome unknown");
        result = 3;
    }
    return result;
}

static int cgi_service_backend_error(const char *error, const char *fallback) {
    if (strcmp(error, "service identity missing") == 0)
        return cgi_error(
            503U, "Service Unavailable", "controller_service_user_unavailable",
            "The local PM3000 service user 'pm3000-rest' is not configured. "
            "Create it and grant the required REST permissions.");
    return cgi_error(503U, "Service Unavailable", "backend_unavailable", fallback);
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

static int authorization_allows_outlet(const pm3000_authorization *authorization,
                                       const char *outlet_id) {
    unsigned int index;
    if (authorization->unrestricted) return 1;
    for (index = 0U; index < authorization->outlet_count; ++index)
        if (strcmp(authorization->outlets[index], outlet_id) == 0) return 1;
    return 0;
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

static int printable_ascii(const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    while (*cursor != 0U) {
        if (*cursor < 0x20U || *cursor > 0x7eU) return 0;
        ++cursor;
    }
    return 1;
}

static int parse_session_request(const unsigned char *body, size_t length,
                                 char username[129], char password[257]) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1, have_username = 0, have_password = 0;
    if (length == 0U || json_character(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[32];
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset;
            break;
        }
        if (!first && json_character(&cursor, ',') != 0) return -1;
        first = 0;
        json_space(&cursor);
        if (json_ascii_string(&cursor, key, sizeof(key)) != 0 ||
            json_character(&cursor, ':') != 0) return -1;
        json_space(&cursor);
        if (strcmp(key, "username") == 0) {
            if (have_username || json_ascii_string(&cursor, username, 129U) != 0 ||
                username[0] == '\0') return -1;
            have_username = 1;
        } else if (strcmp(key, "password") == 0) {
            if (have_password || json_ascii_string(&cursor, password, 257U) != 0 ||
                password[0] == '\0') return -1;
            have_password = 1;
        } else return -1;
    }
    json_space(&cursor);
    return cursor.offset == cursor.length && have_username && have_password &&
           printable_ascii(username) && printable_ascii(password) ? 0 : -1;
}

static int parse_action_request(const unsigned char *body, size_t length,
                                char action[6], char revision[23]) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1, have_action = 0, have_revision = 0;
    action[0] = '\0';
    revision[0] = '\0';
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
            strcpy(action, value);
            have_action = 1;
        } else if (strcmp(key, "inventoryRevision") == 0) {
            char opaque[23]; if (have_revision || strlen(value) != 22U || !opaque_outlet_id(value, opaque)) return -1;
            strcpy(revision, value);
            have_revision = 1;
        } else return -1;
    }
    json_space(&cursor);
    return cursor.offset == cursor.length && have_action ? 0 : -1;
}

static int parse_pdu_action_request(const unsigned char *body, size_t length,
                                    char action[6], char revision[23]) {
    if (parse_action_request(body, length, action, revision) != 0) return -1;
    return revision[0] != '\0' ? 0 : -1;
}

static int parse_selector_action_request(const unsigned char *body, size_t length,
                                         char selector[129], char action[6],
                                         char revision[23]) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1, have_selector = 0, have_action = 0, have_revision = 0;
    selector[0] = '\0'; action[0] = '\0'; revision[0] = '\0';
    if (length == 0U || json_character(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[32], value[129];
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset; break;
        }
        if (!first && json_character(&cursor, ',') != 0) return -1;
        first = 0; json_space(&cursor);
        if (json_ascii_string(&cursor, key, sizeof(key)) != 0 ||
            json_character(&cursor, ':') != 0) return -1;
        json_space(&cursor);
        if (json_ascii_string(&cursor, value, sizeof(value)) != 0) return -1;
        if (strcmp(key, "outlet") == 0) {
            if (have_selector || value[0] == '\0' || !printable_ascii(value)) return -1;
            strcpy(selector, value); have_selector = 1;
        } else if (strcmp(key, "action") == 0) {
            if (have_action || (strcmp(value, "on") != 0 &&
                strcmp(value, "off") != 0 && strcmp(value, "cycle") != 0)) return -1;
            strcpy(action, value); have_action = 1;
        } else if (strcmp(key, "inventoryRevision") == 0) {
            char opaque[23];
            if (have_revision || strlen(value) != 22U ||
                !opaque_outlet_id(value, opaque)) return -1;
            strcpy(revision, value); have_revision = 1;
        } else return -1;
    }
    json_space(&cursor);
    return cursor.offset == cursor.length && have_selector && have_action ? 0 : -1;
}

static int parse_boolean_setting_request(const unsigned char *body, size_t length,
                                         const char *expected_key, int *value) {
    struct json_cursor cursor = {body, length, 0U};
    char key[64];
    int parsed;
    if (length == 0U || json_character(&cursor, '{') != 0) return -1;
    json_space(&cursor);
    if (json_ascii_string(&cursor, key, sizeof(key)) != 0 ||
        strcmp(key, expected_key) != 0 || json_character(&cursor, ':') != 0)
        return -1;
    json_space(&cursor);
    if (cursor.offset + 4U <= cursor.length &&
        memcmp(cursor.data + cursor.offset, "true", 4U) == 0) {
        parsed = 1; cursor.offset += 4U;
    } else if (cursor.offset + 5U <= cursor.length &&
               memcmp(cursor.data + cursor.offset, "false", 5U) == 0) {
        parsed = 0; cursor.offset += 5U;
    } else return -1;
    if (json_character(&cursor, '}') != 0) return -1;
    json_space(&cursor);
    if (cursor.offset != cursor.length) return -1;
    *value = parsed;
    return 0;
}

struct json_string_field {
    const char *key;
    char *value;
    size_t capacity;
    int allow_empty;
    int seen;
};

static int parse_string_object(const unsigned char *body, size_t length,
                               struct json_string_field *fields,
                               size_t field_count) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1;
    size_t index;
    if (field_count == 0U || field_count > 16U || length == 0U ||
        json_character(&cursor, '{') != 0) return -1;
    for (index = 0U; index < field_count; ++index) fields[index].seen = 0;
    for (;;) {
        char key[64];
        struct json_string_field *field = NULL;
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset; break;
        }
        if (!first && json_character(&cursor, ',') != 0) return -1;
        first = 0; json_space(&cursor);
        if (json_ascii_string(&cursor, key, sizeof(key)) != 0 ||
            json_character(&cursor, ':') != 0) return -1;
        for (index = 0U; index < field_count; ++index)
            if (strcmp(key, fields[index].key) == 0) field = &fields[index];
        if (field == NULL || field->seen) return -1;
        json_space(&cursor);
        if (json_ascii_string(&cursor, field->value, field->capacity) != 0 ||
            (!field->allow_empty && field->value[0] == '\0')) return -1;
        field->seen = 1;
    }
    json_space(&cursor);
    if (cursor.offset != cursor.length) return -1;
    for (index = 0U; index < field_count; ++index)
        if (!fields[index].seen) return -1;
    return 0;
}

static int parse_nis_setting_request(const unsigned char *body, size_t length,
                                     char domain_name[100], char address[100]) {
    struct json_string_field fields[] = {
        {"domainName", domain_name, 100U, 0, 0},
        {"address", address, 100U, 0, 0}
    };
    return parse_string_object(body, length, fields,
                               sizeof(fields) / sizeof(fields[0]));
}

static int valid_nis_component(const char *value, int allow_colon) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (*cursor == '\0') return 0;
    while (*cursor != '\0') {
        unsigned char c = *cursor++;
        if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') ||
              (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_' ||
              (allow_colon && c == ':'))) return 0;
    }
    return 1;
}

static int write_json_ascii_string(FILE *output, const char *value) {
    const unsigned char *cursor = (const unsigned char *)value;
    if (fputc('"', output) == EOF) return -1;
    while (*cursor != '\0') {
        unsigned char c = *cursor++;
        if (c < 0x20U) return -1;
        if (c == '"' || c == '\\') {
            if (fputc('\\', output) == EOF) return -1;
        }
        if (fputc((int)c, output) == EOF) return -1;
    }
    return fputc('"', output) == EOF ? -1 : 0;
}

static int parse_password_request(const unsigned char *body, size_t length,
                                  char old_password[257], char new_password[257],
                                  char confirmation[257]) {
    struct json_cursor cursor = {body, length, 0U};
    int first = 1, have_old = 0, have_new = 0, have_confirmation = 0;
    if (length == 0U || json_character(&cursor, '{') != 0) return -1;
    for (;;) {
        char key[32];
        char *destination = NULL;
        int *present = NULL;
        json_space(&cursor);
        if (cursor.offset < cursor.length && cursor.data[cursor.offset] == '}') {
            ++cursor.offset;
            break;
        }
        if (!first && json_character(&cursor, ',') != 0) return -1;
        first = 0;
        json_space(&cursor);
        if (json_ascii_string(&cursor, key, sizeof(key)) != 0 ||
            json_character(&cursor, ':') != 0) return -1;
        json_space(&cursor);
        if (strcmp(key, "oldPassword") == 0) {
            destination = old_password; present = &have_old;
        } else if (strcmp(key, "newPassword") == 0) {
            destination = new_password; present = &have_new;
        } else if (strcmp(key, "confirmation") == 0) {
            destination = confirmation; present = &have_confirmation;
        } else return -1;
        if (*present || json_ascii_string(&cursor, destination, 257U) != 0 ||
            destination[0] == '\0') return -1;
        *present = 1;
    }
    json_space(&cursor);
    return cursor.offset == cursor.length && have_old && have_new &&
           have_confirmation && strcmp(new_password, confirmation) == 0 ? 0 : -1;
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

static int browser_session_authorization(const char *header) {
    return header == NULL || header[0] == '\0' ||
           strncmp(header, "Basic ", 6U) == 0 ||
           strncmp(header, "Digest ", 7U) == 0;
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

static int session_identifier_from_cookie(char identifier[PM3000_SESSION_ID_LENGTH + 1U]) {
    const char *header = getenv("HTTP_COOKIE");
    const char *cursor;
    int found = 0;
    if (header == NULL) return -1;
    cursor = header;
    while (*cursor != '\0') {
        const char *end = strchr(cursor, ';');
        const char *equals;
        const char *name_end;
        const char *value;
        size_t name_length, value_length;
        if (end == NULL) end = cursor + strlen(cursor);
        while (cursor < end && (*cursor == ' ' || *cursor == '\t')) ++cursor;
        while (end > cursor && (end[-1] == ' ' || end[-1] == '\t')) --end;
        equals = memchr(cursor, '=', (size_t)(end - cursor));
        if (equals != NULL) {
            name_end = equals;
            while (name_end > cursor && (name_end[-1] == ' ' || name_end[-1] == '\t')) --name_end;
            name_length = (size_t)(name_end - cursor);
            value = equals + 1;
            value_length = (size_t)(end - value);
            if (name_length == strlen("pm3000_session") &&
                memcmp(cursor, "pm3000_session", name_length) == 0) {
                if (found || value_length != PM3000_SESSION_ID_LENGTH) return -1;
                memcpy(identifier, value, value_length);
                identifier[value_length] = '\0';
                found = 1;
            }
        }
        cursor = *end == ';' ? end + 1 : end;
    }
    return found ? 0 : -1;
}

static int load_request_session(const char *directory, int refresh,
                                pm3000_session *session) {
    char identifier[PM3000_SESSION_ID_LENGTH + 1U];
    char error[80] = {0};
    if (session_identifier_from_cookie(identifier) != 0) return -1;
    return pm3000_session_load(directory, identifier, refresh, session,
                               error, sizeof(error));
}

static void session_cookie_value(const char *identifier, int expire,
                                 char output[160]) {
    if (expire) {
        (void)snprintf(output, 160U,
                       "pm3000_session=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0");
    } else {
        (void)snprintf(output, 160U,
                       "pm3000_session=%s; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=900",
                       identifier);
    }
}

static int run_session_route(const char *method, const char *session_directory,
                             const char *socket_path) {
    char error[160] = {0};
    char cookie[160];
    pm3000_session session;
    const char *authorization = getenv("HTTP_AUTHORIZATION");
    if (!browser_session_authorization(authorization))
        return cgi_error(401U, "Unauthorized", "unauthorized",
                         "Authorization is not accepted for browser sessions.");
    if (strcmp(method, "POST") == 0) {
        unsigned char body[1025];
        char username[129] = {0}, password[257] = {0}, sid[129] = {0};
        unsigned char *navigation = NULL;
        unsigned char *topology = NULL;
        size_t body_length = 0U, navigation_length = 0U, topology_length = 0U;
        int body_result = read_json_body(body, 1024U, &body_length);
        int result;
        if (body_result == 415) {
            memset(body, 0, sizeof(body));
            return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                             "Content-Type must be application/json without content encoding.");
        }
        if (body_result == 413) {
            memset(body, 0, sizeof(body));
            return cgi_error(413U, "Payload Too Large", "payload_too_large",
                             "The request body is too large.");
        }
        if (body_result != 0 ||
            parse_session_request(body, body_length, username, password) != 0) {
            memset(body, 0, sizeof(body));
            memset(password, 0, sizeof(password));
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        }
        result = pm3000_login_session(socket_path, username, password, sid,
                                      &navigation, &navigation_length,
                                      error, sizeof(error));
        memset(password, 0, sizeof(password));
        memset(body, 0, sizeof(body));
        if (result != 0) {
            free(navigation);
            return cgi_error(401U, "Unauthorized", "unauthorized", "Controller login rejected.");
        }
        (void)pm3000_fetch_topology_session(socket_path, sid, &topology,
                                             &topology_length, error,
                                             sizeof(error));
        result = pm3000_session_create(session_directory, username, sid,
                                       navigation, navigation_length,
                                       topology, topology_length, &session,
                                       error, sizeof(error));
        free(topology);
        free(navigation);
        if (result != 0) {
            (void)pm3000_logout_session(socket_path, sid, error, sizeof(error));
            memset(sid, 0, sizeof(sid));
            return cgi_error(503U, "Service Unavailable", "session_store_unavailable",
                             "Session storage is unavailable.");
        }
        memset(sid, 0, sizeof(sid));
        session_cookie_value(session.id, 0, cookie);
        cgi_headers_extra(201U, "Created", cookie);
        return pm3000_session_write_json(stdout, &session) == 0 ? 0 : 1;
    }
    if (strcmp(method, "GET") == 0) {
        if (load_request_session(session_directory, 1, &session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized", "A valid session is required.");
        session_cookie_value(session.id, 0, cookie);
        cgi_headers_extra(200U, "OK", cookie);
        return pm3000_session_write_json(stdout, &session) == 0 ? 0 : 1;
    }
    if (strcmp(method, "DELETE") == 0) {
        int local_result, logout_result;
        if (load_request_session(session_directory, 0, &session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized", "A valid session is required.");
        if (!pm3000_session_csrf_matches(&session, getenv("HTTP_X_CSRF_TOKEN")))
            return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
        local_result = pm3000_session_delete(session_directory, session.id,
                                             error, sizeof(error));
        logout_result = pm3000_logout_session(socket_path, session.sid,
                                              error, sizeof(error));
        memset(session.sid, 0, sizeof(session.sid));
        if (local_result != 0)
            return cgi_error(503U, "Service Unavailable", "logout_incomplete",
                             "Local session teardown could not be confirmed.");
        session_cookie_value("", 1, cookie);
        if (logout_result != 0)
            return cgi_error_extra(503U, "Service Unavailable", "logout_incomplete",
                                   "The local session ended; controller logout was not confirmed.",
                                   cookie);
        cgi_headers_extra(204U, "No Content", cookie);
        return ferror(stdout) ? 1 : 0;
    }
    return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
}

static int deliver_created(const char *response, void *context) {
    (void)context;
    cgi_headers(201U, "Created");
    if (fputs(response, stdout) == EOF || fflush(stdout) != 0 || ferror(stdout)) return -1;
    return 0;
}

static int run_token_route(const char *method, const char *path, const char *store_path,
                           const pm3000_session *session) {
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
    if (session != NULL) {
        if (!session->can_manage_tokens)
            return cgi_error(403U, "Forbidden", "forbidden", "Token administration is not permitted.");
        if (strcmp(method, "GET") != 0 &&
            !pm3000_session_csrf_matches(session, getenv("HTTP_X_CSRF_TOKEN")))
            return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
        auth = 0;
    } else {
        auth = admin_bearer(store_path, &token);
    }
    if (auth == 401) return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
    if (auth == 403) return cgi_error(403U, "Forbidden", "forbidden", "Administrator scope is required.");
    if (auth != 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Token administration is unavailable.");
    if (strcmp(path, "/api/v1/tokens") == 0) {
        if (strcmp(method, "GET") == 0) {
            result = session != NULL ? pm3000_token_list_session(store_path, &response) :
                                       pm3000_token_list(store_path, token, &response);
            if (result != PM3000_TOKEN_OK) return admin_error(result);
            cgi_headers(200U, "OK"); fputs(response, stdout); free(response);
            return ferror(stdout) ? 1 : 0;
        }
        if (strcmp(method, "POST") == 0) {
            unsigned char body[2049]; size_t length = 0U; int body_result = read_json_body(body, 2048U, &length);
            if (body_result == 415) return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type", "Content-Type must be application/json.");
            if (body_result == 413) return cgi_error(413U, "Payload Too Large", "payload_too_large", "The request body is too large.");
            if (body_result != 0) return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
            result = session != NULL ?
                pm3000_token_create_session(store_path, body, length, deliver_created, NULL) :
                pm3000_token_create(store_path, token, body, length, deliver_created, NULL);
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
            result = session != NULL ? pm3000_token_revoke_session(store_path, token_id) :
                                       pm3000_token_revoke(store_path, token, token_id);
        } else if (strcmp(suffix, "/disable") == 0 || strcmp(suffix, "/enable") == 0) {
            if (strcmp(method, "POST") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
            result = session != NULL ?
                pm3000_token_set_enabled_session(store_path, token_id, strcmp(suffix, "/enable") == 0) :
                pm3000_token_set_enabled(store_path, token, token_id, strcmp(suffix, "/enable") == 0);
        } else return cgi_error(404U, "Not Found", "not_found", "Route not found.");
        if (result != PM3000_TOKEN_OK) return admin_error(result);
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
    }
}

static int settings_lock_fd = -1;

static void close_settings_lock(void) {
    if (settings_lock_fd >= 0) {
        close(settings_lock_fd);
        settings_lock_fd = -1;
    }
}

static int acquire_settings_write_lock(void) {
    const char *directory = configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions");
    char path[1024];
    struct stat metadata;
    int amount;
    if (settings_lock_fd >= 0) return 0;
    amount = snprintf(path, sizeof(path), "%s/settings-write.lock", directory);
    if (amount < 0 || (size_t)amount >= sizeof(path)) return -1;
    settings_lock_fd = open(path, O_RDWR | O_CREAT | O_NOFOLLOW, 0600);
    if (settings_lock_fd < 0 || fstat(settings_lock_fd, &metadata) != 0 ||
        !S_ISREG(metadata.st_mode) || metadata.st_nlink != 1 ||
        metadata.st_uid != geteuid() || (metadata.st_mode & 077U) != 0U ||
        flock(settings_lock_fd, LOCK_EX | LOCK_NB) != 0) {
        close_settings_lock();
        return -1;
    }
    if (atexit(close_settings_lock) != 0) {
        close_settings_lock();
        return -1;
    }
    return 0;
}

static int write_fixed_setting(pm3000_fixed_form_kind kind,
                               const struct pm3000_fixed_snapshot *snapshot) {
    unsigned int index;
    cgi_settings_headers(snapshot->revision);
    if (kind == PM3000_FORM_HELP_LANGUAGE) {
        fputs("{\"applianceLanguage\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[0]) != 0) return 1;
        fputs(",\"url\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[1]) != 0) return 1;
        fputs(",\"allowedLanguages\":[", stdout);
        for (index = 0U; index < snapshot->form.choice_count; ++index) {
            if (index > 0U) fputc(',', stdout);
            if (write_json_ascii_string(stdout, snapshot->form.choices[index]) != 0) return 1;
        }
        fputs("],\"revision\":", stdout);
    } else if (kind == PM3000_FORM_DATA_BUFFERING) {
        fprintf(stdout,
                "{\"localSize\":%s,\"localSegments\":%s,\"nfsServer\":",
                snapshot->form.values[0], snapshot->form.values[1]);
        if (write_json_ascii_string(stdout, snapshot->form.values[2]) != 0) return 1;
        fputs(",\"nfsPath\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[3]) != 0) return 1;
        fprintf(stdout,
                ",\"nfsSize\":%s,\"nfsSegments\":%s,\"syslogFacility\":",
                snapshot->form.values[4], snapshot->form.values[5]);
        if (write_json_ascii_string(stdout, snapshot->form.values[6]) != 0) return 1;
        fputs(",\"revision\":", stdout);
    } else if (kind == PM3000_FORM_TIME_ZONE) {
        unsigned int written = 0U;
        fputs("{\"mode\":", stdout);
        if (write_json_ascii_string(stdout,
                strcmp(snapshot->form.values[0], "yes") == 0 ? "custom" : "predefined") != 0) return 1;
        fputs(",\"predefined\":{\"selected\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[1]) != 0) return 1;
        fputs(",\"choices\":[", stdout);
        for (index = 0U; index < snapshot->form.choice_count; ++index) {
            if (snapshot->form.choice_fields[index] != 1U) continue;
            if (written++ > 0U) fputc(',', stdout);
            if (write_json_ascii_string(stdout, snapshot->form.choices[index]) != 0) return 1;
        }
        fputs("]},\"custom\":{\"name\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[2]) != 0) return 1;
        fputs(",\"standardAcronym\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[3]) != 0) return 1;
        fputs(",\"gmtOffset\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[4]) != 0) return 1;
        fprintf(stdout, ",\"dst\":{\"enabled\":%s,\"acronym\":",
                snapshot->form.values[5]);
        if (write_json_ascii_string(stdout, snapshot->form.values[6]) != 0) return 1;
        fputs(",\"saveTime\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[7]) != 0) return 1;
        fputs(",\"start\":{\"month\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[8]) != 0) return 1;
        fputs(",\"week\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[9]) != 0) return 1;
        fputs(",\"weekday\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[10]) != 0) return 1;
        fputs(",\"hour\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[11]) != 0) return 1;
        fputs("},\"end\":{\"month\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[12]) != 0) return 1;
        fputs(",\"week\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[13]) != 0) return 1;
        fputs(",\"weekday\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[14]) != 0) return 1;
        fputs(",\"hour\":", stdout);
        if (write_json_ascii_string(stdout, snapshot->form.values[15]) != 0) return 1;
        fputs("}}},\"revision\":", stdout);
    } else {
        fprintf(stdout,
                "{\"sessionLoggingEnabled\":%s,\"destination\":",
                snapshot->form.values[0]);
        if (write_json_ascii_string(stdout, snapshot->form.values[1]) != 0) return 1;
        fprintf(stdout, ",\"timestampEnabled\":%s,\"alertsEnabled\":%s,\"alertStrings\":[",
                strcmp(snapshot->form.values[2], "yes") == 0 ? "true" : "false",
                snapshot->form.values[3]);
        for (index = 4U; index < 14U; ++index) {
            if (index > 4U) fputc(',', stdout);
            if (write_json_ascii_string(stdout, snapshot->form.values[index]) != 0) return 1;
        }
        fputs("],\"allowedDestinations\":[\"local\",\"nfs\",\"syslog\",\"dsview\"],\"revision\":", stdout);
    }
    if (write_json_ascii_string(stdout, snapshot->revision) != 0) return 1;
    fputs("}\n", stdout);
    return ferror(stdout) ? 1 : 0;
}

static int run_fixed_setting_route(const char *method,
                                   pm3000_fixed_form_kind kind,
                                   const pm3000_session *session,
                                   const char *socket_path) {
    unsigned char *response = NULL;
    size_t response_length = 0U;
    struct pm3000_fixed_snapshot current, confirmed;
    struct pm3000_fixed_input input;
    char error[160] = {0};
    const char *path = pm3000_fixed_path(kind);
    int result;
    if (strcmp(method, "GET") == 0) {
        if (pm3000_fetch_fixed_setting_session(socket_path, session->sid, path,
                                                &response, &response_length,
                                                error, sizeof(error)) != 0)
            return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                             "The settings backend was unavailable.");
        result = pm3000_fixed_parse_backend(kind, response, response_length, &current);
        free(response);
        if (result != 0)
            return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                             "The settings response was invalid.");
        return write_fixed_setting(kind, &current);
    }
    if (strcmp(method, "PUT") != 0)
        return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    if (!pm3000_session_csrf_matches(session, getenv("HTTP_X_CSRF_TOKEN")))
        return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
    {
        const char *if_match = getenv("HTTP_IF_MATCH");
        unsigned char body[4097] = {0};
        size_t body_length = 0U;
        size_t etag_index;
        int body_result;
        char form_payload[8192];
        if (if_match == NULL || if_match[0] == '\0')
            return cgi_error(428U, "Precondition Required", "precondition_required",
                             "A strong If-Match revision is required.");
        if (strlen(if_match) != 66U || if_match[0] != '"' || if_match[65] != '"')
            return cgi_error(400U, "Bad Request", "bad_request", "If-Match is invalid.");
        for (etag_index = 1U; etag_index < 65U; ++etag_index)
            if (!((if_match[etag_index] >= '0' && if_match[etag_index] <= '9') ||
                  (if_match[etag_index] >= 'a' && if_match[etag_index] <= 'f')))
                return cgi_error(400U, "Bad Request", "bad_request", "If-Match is invalid.");
        body_result = read_json_body(body, 4096U, &body_length);
        if (body_result == 415)
            return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                             "Content-Type must be application/json without content encoding.");
        if (body_result == 413)
            return cgi_error(413U, "Payload Too Large", "payload_too_large",
                             "The request body is too large.");
        if (body_result != 0 || pm3000_fixed_parse_request(kind, body, body_length, &input) != 0)
            return cgi_error(400U, "Bad Request", "bad_request",
                             "The complete settings request is invalid.");
        if (acquire_settings_write_lock() != 0)
            return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                             "The settings write lock was unavailable.");
        if (pm3000_fetch_fixed_setting_session(socket_path, session->sid, path,
                                                &response, &response_length,
                                                error, sizeof(error)) != 0)
            return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                             "The settings backend was unavailable.");
        result = pm3000_fixed_parse_backend(kind, response, response_length, &current);
        free(response); response = NULL; response_length = 0U;
        if (result != 0)
            return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                             "The settings response was invalid.");
        if (strcmp(if_match, current.revision) != 0)
            return cgi_error(412U, "Precondition Failed", "revision_changed",
                             "The setting changed; reload it before saving.");
        if (kind == PM3000_FORM_HELP_LANGUAGE &&
            !pm3000_fixed_language_allowed(&current, input.values[0]))
            return cgi_error(400U, "Bad Request", "bad_request",
                             "The selected language is not currently available.");
        if (pm3000_fixed_merge_inactive(kind, &current, &input) != 0 ||
            pm3000_fixed_serialize(kind, &input, form_payload, sizeof(form_payload)) != 0)
            return cgi_error(400U, "Bad Request", "bad_request",
                             "The complete settings request is invalid.");
        result = pm3000_save_fixed_setting_session(socket_path, session->sid, path,
                                                    form_payload, &response,
                                                    &response_length, error,
                                                    sizeof(error));
        memset(form_payload, 0, sizeof(form_payload));
        if (result == 3) {
            free(response);
            return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                             "The setting write may have been dispatched; do not retry automatically.");
        }
        if (result != 0) {
            free(response);
            return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                             "The setting write backend was unavailable.");
        }
        result = pm3000_fixed_parse_backend(kind, response, response_length, &confirmed);
        free(response);
        if (result != 0 || !pm3000_fixed_values_match(kind, &confirmed, &input))
            return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                             "The setting write outcome is unknown; do not retry automatically.");
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
    }
}

static int run_cgi(void) {
    const char *method = getenv("REQUEST_METHOD");
    const char *path = getenv("PATH_INFO");
    const char *script_name = getenv("SCRIPT_NAME");
    const char *https = getenv("HTTPS");
    char routed_path[256];
    const char *header;
    const char *token;
    pm3000_authorization authorization;
    pm3000_session gui_session;
    unsigned char *response = NULL;
    size_t response_length = 0;
    char error[160] = {0};
    int auth_result;
    int detail_request = 0;
    int using_session = 0;
    char requested_outlet[23] = {0};
    if (path != NULL && strncmp(path, "/api/v1", 7U) != 0 &&
        script_name != NULL && strcmp(script_name, "/api/v1") == 0 && path[0] == '/') {
        int written = snprintf(routed_path, sizeof(routed_path), "%s%s", script_name, path);
        if (written < 0 || (size_t)written >= sizeof(routed_path)) {
            return cgi_error(400U, "Bad Request", "bad_request", "The request path is invalid.");
        }
        path = routed_path;
    }
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
    if (method != NULL && path != NULL && strcmp(path, "/api/v1/session") == 0) {
        return run_session_route(
            method,
            configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
            configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"));
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/session/password") == 0) {
        unsigned char body[2049] = {0};
        char old_password[257] = {0}, new_password[257] = {0}, confirmation[257] = {0};
        size_t body_length = 0U;
        int body_result, result;
        if (strcmp(method, "POST") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for password changes.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized", "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, "units.change_password"))
            return cgi_error(403U, "Forbidden", "forbidden", "Password change is not permitted.");
        if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
            return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
        body_result = read_json_body(body, 2048U, &body_length);
        if (body_result == 415) {
            memset(body, 0, sizeof(body));
            return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                             "Content-Type must be application/json without content encoding.");
        }
        if (body_result == 413) {
            memset(body, 0, sizeof(body));
            return cgi_error(413U, "Payload Too Large", "payload_too_large",
                             "The request body is too large.");
        }
        if (body_result != 0 || parse_password_request(
                body, body_length, old_password, new_password, confirmation) != 0) {
            memset(body, 0, sizeof(body));
            memset(old_password, 0, sizeof(old_password));
            memset(new_password, 0, sizeof(new_password));
            memset(confirmation, 0, sizeof(confirmation));
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        }
        result = pm3000_change_password_session(
            configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
            gui_session.sid, old_password, new_password, confirmation,
            error, sizeof(error));
        memset(body, 0, sizeof(body));
        memset(old_password, 0, sizeof(old_password));
        memset(new_password, 0, sizeof(new_password));
        memset(confirmation, 0, sizeof(confirmation));
        if (result == 3)
            return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                             "The password change may have been dispatched; do not retry automatically.");
        if (result != 0)
            return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                             "The password change was not confirmed.");
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
    }
    if (method != NULL && path != NULL &&
        (strcmp(path, "/api/v1/settings/help-language") == 0 ||
         strcmp(path, "/api/v1/settings/data-buffering") == 0 ||
         strcmp(path, "/api/v1/settings/appliance-logging") == 0 ||
         strcmp(path, "/api/v1/settings/time-zone") == 0)) {
        pm3000_fixed_form_kind kind;
        if (strcmp(path, "/api/v1/settings/help-language") == 0)
            kind = PM3000_FORM_HELP_LANGUAGE;
        else if (strcmp(path, "/api/v1/settings/data-buffering") == 0)
            kind = PM3000_FORM_DATA_BUFFERING;
        else if (strcmp(path, "/api/v1/settings/appliance-logging") == 0)
            kind = PM3000_FORM_APPLIANCE_LOGGING;
        else
            kind = PM3000_FORM_TIME_ZONE;
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this browser setting.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if ((kind == PM3000_FORM_HELP_LANGUAGE && !gui_session.can_help_language) ||
            (kind == PM3000_FORM_DATA_BUFFERING && !gui_session.can_data_buffering) ||
            (kind == PM3000_FORM_APPLIANCE_LOGGING && !gui_session.can_appliance_logging) ||
            (kind == PM3000_FORM_TIME_ZONE && !gui_session.can_time_zone))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "The exact configuration write capability is required.");
        return run_fixed_setting_route(
            method, kind, &gui_session,
            configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"));
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/settings/security/dsview") == 0) {
        static const char permission[] = "units.applianceSettings.security.SecurityDSView";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this browser setting.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "DSView security configuration is not permitted.");
        if (strcmp(method, "GET") == 0) {
            int allow_dsview;
            if (pm3000_fetch_dsview_setting_session(
                    socket_path, gui_session.sid, &response, &response_length,
                    error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The DSView setting backend was unavailable.");
            if (pm3000_xml_dsview_value(response, response_length,
                                         permission, &allow_dsview) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The DSView setting response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fprintf(stdout, "{\"allowDSView\":%s}\n", allow_dsview ? "true" : "false");
            return ferror(stdout) ? 1 : 0;
        }
        if (strcmp(method, "PUT") == 0) {
            unsigned char body[1025] = {0};
            size_t body_length = 0U;
            int allow_dsview, body_result, result;
            if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
                return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
            body_result = read_json_body(body, 1024U, &body_length);
            if (body_result == 415)
                return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                                 "Content-Type must be application/json without content encoding.");
            if (body_result == 413)
                return cgi_error(413U, "Payload Too Large", "payload_too_large",
                                 "The request body is too large.");
            if (body_result != 0 || parse_boolean_setting_request(
                    body, body_length, "allowDSView", &allow_dsview) != 0)
                return cgi_error(400U, "Bad Request", "bad_request",
                                 "Expected exactly one allowDSView boolean.");
            result = pm3000_save_dsview_setting_session(
                socket_path, gui_session.sid, allow_dsview, error, sizeof(error));
            if (result == 3)
                return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                                 "The DSView setting may have been dispatched; do not retry automatically.");
            if (result != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The DSView setting was not confirmed.");
            cgi_headers(204U, "No Content");
            return ferror(stdout) ? 1 : 0;
        }
        return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/settings/authentication/nis") == 0) {
        static const char permission[] = "units.authentication.authenticationservers.nis";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this browser setting.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "NIS configuration is not permitted.");
        if (strcmp(method, "GET") == 0) {
            char domain_name[100], address[100];
            if (pm3000_fetch_nis_setting_session(
                    socket_path, gui_session.sid, &response, &response_length,
                    error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The NIS setting backend was unavailable.");
            if (pm3000_xml_nis_values(response, response_length, permission,
                                       domain_name, sizeof(domain_name),
                                       address, sizeof(address)) != 0 ||
                !valid_nis_component(domain_name, 0) ||
                !valid_nis_component(address, 1)) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The NIS setting response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"domainName\":", stdout);
            if (write_json_ascii_string(stdout, domain_name) != 0) return 1;
            fputs(",\"address\":", stdout);
            if (write_json_ascii_string(stdout, address) != 0) return 1;
            fputs("}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
        if (strcmp(method, "PUT") == 0) {
            unsigned char body[1025] = {0};
            size_t body_length = 0U;
            char domain_name[100], address[100];
            int body_result, result;
            if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
                return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
            body_result = read_json_body(body, 1024U, &body_length);
            if (body_result == 415)
                return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                                 "Content-Type must be application/json without content encoding.");
            if (body_result == 413)
                return cgi_error(413U, "Payload Too Large", "payload_too_large",
                                 "The request body is too large.");
            if (body_result != 0 || parse_nis_setting_request(
                    body, body_length, domain_name, address) != 0 ||
                !valid_nis_component(domain_name, 0) ||
                !valid_nis_component(address, 1))
                return cgi_error(400U, "Bad Request", "bad_request",
                                 "Expected complete non-empty domainName and address strings.");
            result = pm3000_save_nis_setting_session(
                socket_path, gui_session.sid, domain_name, address,
                error, sizeof(error));
            memset(domain_name, 0, sizeof(domain_name));
            memset(address, 0, sizeof(address));
            if (result == 3)
                return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                                 "The NIS setting may have been dispatched; do not retry automatically.");
            if (result != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The NIS setting was not confirmed.");
            cgi_headers(204U, "No Content");
            return ferror(stdout) ? 1 : 0;
        }
        return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/system/information") == 0) {
        static const char permission[] = "units.applianceSettings.information";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "System information is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_sysinfo info;
            if (pm3000_fetch_sysinfo_session(socket_path, gui_session.sid,
                                              &response, &response_length,
                                              error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The system information backend was unavailable.");
            if (pm3000_xml_system_information(response, response_length, &info) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The system information response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"modelNumber\":", stdout);
            if (write_json_ascii_string(stdout, info.model_number) != 0) return 1;
            fputs(",\"bootCodeVersion\":", stdout);
            if (write_json_ascii_string(stdout, info.boot_code_version) != 0) return 1;
            fputs(",\"firmwareVersion\":", stdout);
            if (write_json_ascii_string(stdout, info.firmware_version) != 0) return 1;
            fputs(",\"bootedFrom\":", stdout);
            if (write_json_ascii_string(stdout, info.booted_from) != 0) return 1;
            fputs(",\"cpu\":", stdout);
            if (write_json_ascii_string(stdout, info.cpu) != 0) return 1;
            fputs(",\"revision\":", stdout);
            if (write_json_ascii_string(stdout, info.revision) != 0) return 1;
            fputs(",\"bogomips\":", stdout);
            if (write_json_ascii_string(stdout, info.bogomips) != 0) return 1;
            fputs("}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/system/usage/memory") == 0) {
        static const char permission[] = "units.applianceSettings.usage.memory";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "Memory usage is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_memory_table table;
            unsigned int i;
            if (pm3000_fetch_memory_session(socket_path, gui_session.sid,
                                             &response, &response_length,
                                             error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The memory usage backend was unavailable.");
            if (pm3000_xml_memory_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The memory usage response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"rows\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"name\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].name) != 0) return 1;
                fputs(",\"value\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].value) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/system/usage/flash") == 0) {
        static const char permission[] = "units.applianceSettings.usage.flashUsage";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "Flash usage is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_flash_table table;
            unsigned int i;
            if (pm3000_fetch_flash_session(socket_path, gui_session.sid,
                                            &response, &response_length,
                                            error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The flash usage backend was unavailable.");
            if (pm3000_xml_flash_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The flash usage response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"rows\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"filesystem\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].filesystem) != 0) return 1;
                fputs(",\"blocks1k\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].blocks1k) != 0) return 1;
                fputs(",\"used\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].used) != 0) return 1;
                fputs(",\"available\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].available) != 0) return 1;
                fputs(",\"usePercentage\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].use_percentage) != 0) return 1;
                fputs(",\"mountedOn\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].mounted_on) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/monitoring/network/devices") == 0) {
        static const char permission[] = "units.monitoring.networkmon.monitoringDevice";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "Network device monitoring is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_netdev_table table;
            unsigned int i;
            if (pm3000_fetch_netdev_session(socket_path, gui_session.sid,
                                             &response, &response_length,
                                             error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The network device backend was unavailable.");
            if (pm3000_xml_netdev_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The network device response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"devices\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"name\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].device_name) != 0) return 1;
                fputs(",\"status\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].status) != 0) return 1;
                fputs(",\"ipv4Address\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].ipv4_address) != 0) return 1;
                fputs(",\"ipv4Mask\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].ipv4_mask) != 0) return 1;
                fputs(",\"ipv6Address\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].ipv6_address) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/monitoring/network/routes/ipv4") == 0) {
        static const char permission[] = "units.monitoring.networkmon.monitoringIpv4RouteTable";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "IPv4 route monitoring is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_route4_table table;
            unsigned int i;
            if (pm3000_fetch_route4_session(socket_path, gui_session.sid,
                                             &response, &response_length,
                                             error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The IPv4 route backend was unavailable.");
            if (pm3000_xml_route4_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The IPv4 route response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"routes\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"destination\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].destination) != 0) return 1;
                fputs(",\"gateway\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].gateway) != 0) return 1;
                fputs(",\"genmask\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].genmask) != 0) return 1;
                fputs(",\"flags\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].flags) != 0) return 1;
                fputs(",\"metric\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].metric) != 0) return 1;
                fputs(",\"ref\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].ref) != 0) return 1;
                fputs(",\"use\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].use) != 0) return 1;
                fputs(",\"iface\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].iface) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/monitoring/network/routes/ipv6") == 0) {
        static const char permission[] = "units.monitoring.networkmon.monitoringIpv6RouteTable";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "IPv6 route monitoring is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_route6_table table;
            unsigned int i;
            if (pm3000_fetch_route6_session(socket_path, gui_session.sid,
                                             &response, &response_length,
                                             error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The IPv6 route backend was unavailable.");
            if (pm3000_xml_route6_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The IPv6 route response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"routes\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"destination\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].destination) != 0) return 1;
                fputs(",\"nextHop\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].next_hop) != 0) return 1;
                fputs(",\"flags\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].flags) != 0) return 1;
                fputs(",\"metric\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].metric) != 0) return 1;
                fputs(",\"ref\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].ref) != 0) return 1;
                fputs(",\"use\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].use) != 0) return 1;
                fputs(",\"iface\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].iface) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        strcmp(path, "/api/v1/monitoring/serial-ports") == 0) {
        static const char permission[] = "units.monitoring.serialstatistics";
        const char *socket_path = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (!browser_session_authorization(getenv("HTTP_AUTHORIZATION")))
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Bearer authentication is not accepted for this route.");
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session authentication required.");
        if (!pm3000_session_has_path(&gui_session, permission))
            return cgi_error(403U, "Forbidden", "forbidden",
                             "Serial port monitoring is not permitted.");
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed",
                             "Method not allowed.");
        {
            struct pm3000_serial_table table;
            unsigned int i;
            if (pm3000_fetch_serial_session(socket_path, gui_session.sid,
                                             &response, &response_length,
                                             error, sizeof(error)) != 0)
                return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                                 "The serial port backend was unavailable.");
            if (pm3000_xml_serial_table(response, response_length, &table) != 0) {
                free(response);
                return cgi_error(502U, "Bad Gateway", "backend_protocol_error",
                                 "The serial port response was invalid.");
            }
            free(response);
            cgi_headers(200U, "OK");
            fputs("{\"ports\":[", stdout);
            for (i = 0U; i < table.row_count; ++i) {
                if (i > 0U) fputc(',', stdout);
                fputs("{\"deviceName\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].device_name) != 0) return 1;
                fputs(",\"portProfile\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].port_profile) != 0) return 1;
                fputs(",\"speed\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].speed) != 0) return 1;
                fputs(",\"signals\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].signals) != 0) return 1;
                fputs(",\"txBytes\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].tx_bytes) != 0) return 1;
                fputs(",\"rxBytes\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].rx_bytes) != 0) return 1;
                fputs(",\"frameError\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].frame_error) != 0) return 1;
                fputs(",\"parityError\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].parity_error) != 0) return 1;
                fputs(",\"brk\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].brk) != 0) return 1;
                fputs(",\"overrun\":", stdout);
                if (write_json_ascii_string(stdout, table.rows[i].overrun) != 0) return 1;
                fputc('}', stdout);
            }
            fputs("]}\n", stdout);
            return ferror(stdout) ? 1 : 0;
        }
    }
    if (method != NULL && path != NULL &&
        (strcmp(path, "/api/v1/tokens") == 0 ||
         strncmp(path, "/api/v1/tokens/", 15U) == 0)) {
        const pm3000_session *session = NULL;
        if (browser_session_authorization(getenv("HTTP_AUTHORIZATION"))) {
            if (load_request_session(
                    configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                    1, &gui_session) != 0)
                return cgi_error(401U, "Unauthorized", "unauthorized",
                                 "Session or Bearer authentication required.");
            session = &gui_session;
        }
        return run_token_route(
            method, path,
            configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
            session);
    }
    if (method != NULL && path != NULL && strcmp(path, "/api/v1/pdus") == 0) {
        if (strcmp(method, "GET") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        header = getenv("HTTP_AUTHORIZATION");
        if (!browser_session_authorization(header)) {
            if (strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' || strchr(header + 7, ' ') != NULL)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
            auth_result = pm3000_authorize(configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
                                           header + 7, "read", NULL, &authorization, error, sizeof(error));
            if (auth_result < 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
            if (!authorization.authenticated) return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
            if (!authorization.authorized || !authorization.unrestricted)
                return cgi_error(403U, "Forbidden", "forbidden", "PDU inventory requires an unrestricted token.");
            auth_result = service_fetch_pdus(
                configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                &response, &response_length, error, sizeof(error));
        } else {
            if (load_request_session(configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"), 1, &gui_session) != 0)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Session or Bearer authentication required.");
            if (!pm3000_session_has_path(&gui_session, "units.powermanagement.pdu_management"))
                return cgi_error(403U, "Forbidden", "forbidden", "PDU inventory is not permitted.");
            auth_result = pm3000_fetch_pdus_session(configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                                                    gui_session.sid, &response, &response_length, error, sizeof(error));
        }
        if (auth_result != 0) {
            free(response);
            return cgi_service_backend_error(error, "PDU backend unavailable.");
        }
        if (pm3000_project_pdus_bytes(response, (unsigned long)response_length, NULL, error, sizeof(error)) != 0) {
            free(response); return cgi_error(502U, "Bad Gateway", "backend_protocol_error", "Backend response rejected.");
        }
        cgi_headers(200U, "OK");
        auth_result = pm3000_project_pdus_bytes(response, (unsigned long)response_length, stdout, error, sizeof(error));
        free(response); return auth_result == 0 && !ferror(stdout) ? 0 : 1;
    }
    if (method != NULL && path != NULL && strlen(path) == 43U &&
        memcmp(path, "/api/v1/pdus/", 13U) == 0 && memcmp(path + 35U, "/actions", 8U) == 0) {
        char pdu_id[23], action[6], revision[23]; unsigned char body[1025]; size_t body_length = 0U; int body_result;
        if (!opaque_outlet_id(path + 13U, pdu_id)) return cgi_error(404U, "Not Found", "not_found", "PDU not found.");
        if (strcmp(method, "POST") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        body_result = read_json_body(body, 1024U, &body_length);
        if (body_result == 415) return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type", "Content-Type must be application/json without content encoding.");
        if (body_result == 413) return cgi_error(413U, "Payload Too Large", "payload_too_large", "The request body is too large.");
        if (body_result != 0 || parse_pdu_action_request(body, body_length, action, revision) != 0)
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        header = getenv("HTTP_AUTHORIZATION");
        if (!browser_session_authorization(header)) {
            if (strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' || strchr(header + 7, ' ') != NULL)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
            auth_result = pm3000_authorize(configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
                                           header + 7, "control", NULL, &authorization, error, sizeof(error));
            if (auth_result < 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
            if (!authorization.authenticated) return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
            if (!authorization.authorized || !authorization.unrestricted)
                return cgi_error(403U, "Forbidden", "forbidden", "PDU actions require an unrestricted control token.");
            auth_result = service_apply_pdu_action(
                configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                pdu_id, revision, action, error, sizeof(error));
        } else {
            if (load_request_session(configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"), 1, &gui_session) != 0)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Session or Bearer authentication required.");
            if (!pm3000_session_has_path(&gui_session, "units.powermanagement.pdu_management"))
                return cgi_error(403U, "Forbidden", "forbidden", "PDU control is not permitted.");
            if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
                return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
            auth_result = pm3000_apply_pdu_action_session(configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                                                          gui_session.sid, pdu_id, revision, action, error, sizeof(error));
        }
        if (auth_result == 1) return cgi_error(409U, "Conflict", "inventory_changed", "Inventory changed; refresh before retrying.");
        if (auth_result == 2) return cgi_error(404U, "Not Found", "not_found", "PDU not found.");
        if (auth_result == 4) return cgi_error(403U, "Forbidden", "forbidden", "PDU control is not permitted.");
        if (auth_result == 3) return cgi_error(503U, "Service Unavailable", "action_outcome_unknown", "The PDU action may have been dispatched; do not retry automatically.");
        if (auth_result != 0)
            return cgi_service_backend_error(error, "PDU action was not confirmed.");
        cgi_headers(204U, "No Content"); return ferror(stdout) ? 1 : 0;
    }
    if (method != NULL && path != NULL && strcmp(path, "/api/v1/outlets/actions") == 0) {
        char selector[129], outlet_id[23], action[6], revision[23];
        unsigned char body[1025]; size_t body_length = 0U; int body_result, resolve_result;
        const char *action_socket = configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket");
        if (strcmp(method, "POST") != 0)
            return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        body_result = read_json_body(body, 1024U, &body_length);
        if (body_result == 415)
            return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type",
                             "Content-Type must be application/json without content encoding.");
        if (body_result == 413)
            return cgi_error(413U, "Payload Too Large", "payload_too_large",
                             "The request body is too large.");
        if (body_result != 0 || parse_selector_action_request(
                body, body_length, selector, action, revision) != 0)
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        header = getenv("HTTP_AUTHORIZATION");
        if (!browser_session_authorization(header)) {
            if (strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' ||
                strchr(header + 7, ' ') != NULL)
                return cgi_error(401U, "Unauthorized", "unauthorized",
                                 "Bearer authentication required.");
            auth_result = pm3000_authorize(
                configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
                header + 7, "control", NULL, &authorization, error, sizeof(error));
            if (auth_result < 0)
                return cgi_error(503U, "Service Unavailable", "token_store_unavailable",
                                 "Authentication store unavailable.");
            if (!authorization.authenticated)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
            if (!authorization.authorized)
                return cgi_error(403U, "Forbidden", "forbidden",
                                 "Token does not authorize outlet control.");
            resolve_result = service_resolve_outlet_selector(
                action_socket, selector, revision, outlet_id, error, sizeof(error));
            if (resolve_result == 0 && !authorization_allows_outlet(&authorization, outlet_id))
                return cgi_error(403U, "Forbidden", "forbidden",
                                 "Token does not authorize this outlet action.");
            if (resolve_result == 0)
                auth_result = service_apply_outlet_action(
                    action_socket, outlet_id, revision, action, error, sizeof(error));
        } else {
            unsigned char *topology = NULL; size_t topology_length = 0U; char identity[256];
            if (load_request_session(
                    configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                    1, &gui_session) != 0)
                return cgi_error(401U, "Unauthorized", "unauthorized",
                                 "Session or Bearer authentication required.");
            if (!gui_session.can_control_power)
                return cgi_error(403U, "Forbidden", "forbidden", "Power control is not permitted.");
            if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
                return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
            resolve_result = pm3000_fetch_topology_session(
                action_socket, gui_session.sid, &topology, &topology_length, error, sizeof(error));
            if (resolve_result == 0)
                resolve_result = pm3000_resolve_outlet_selector(
                    topology, (unsigned long)topology_length, selector, revision,
                    outlet_id, identity, sizeof(identity), error, sizeof(error));
            free(topology); memset(identity, 0, sizeof(identity));
            if (resolve_result == 0)
                auth_result = pm3000_apply_outlet_action_session(
                    action_socket, gui_session.sid, outlet_id, revision, action,
                    error, sizeof(error));
        }
        if (resolve_result == 1)
            return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        if (resolve_result == 2)
            return cgi_error(409U, "Conflict", "inventory_changed",
                             "Refresh the outlet inventory and retry.");
        if (resolve_result == 5)
            return cgi_error(409U, "Conflict", "outlet_name_ambiguous",
                             "The outlet name is not unique; use the opaque outlet ID.");
        if (resolve_result != 0)
            return cgi_service_backend_error(error, "Outlet selector could not be resolved.");
        if (auth_result == 1)
            return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        if (auth_result == 2)
            return cgi_error(409U, "Conflict", "inventory_changed",
                             "Refresh the outlet inventory and retry.");
        if (auth_result == 3)
            return cgi_error(503U, "Service Unavailable", "action_outcome_unknown",
                             "The outlet action may have been dispatched; do not retry automatically.");
        if (auth_result != 0)
            return cgi_service_backend_error(error, "Outlet action was not confirmed.");
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
    }
    if (method != NULL && path != NULL && strlen(path) == 46U &&
        memcmp(path, "/api/v1/outlets/", 16U) == 0 && memcmp(path + 38U, "/actions", 8U) == 0) {
        char outlet_id[23], action[6], revision[23]; unsigned char body[1025]; size_t body_length = 0U; int body_result;
        if (!opaque_outlet_id(path + 16U, outlet_id)) return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        if (strcmp(method, "POST") != 0) return cgi_error(405U, "Method Not Allowed", "method_not_allowed", "Method not allowed.");
        body_result = read_json_body(body, 1024U, &body_length);
        if (body_result == 415) return cgi_error(415U, "Unsupported Media Type", "unsupported_media_type", "Content-Type must be application/json without content encoding.");
        if (body_result == 413) return cgi_error(413U, "Payload Too Large", "payload_too_large", "The request body is too large.");
        if (body_result != 0 || parse_action_request(body, body_length, action, revision) != 0)
            return cgi_error(400U, "Bad Request", "bad_request", "The request body is invalid.");
        header = getenv("HTTP_AUTHORIZATION");
        if (!browser_session_authorization(header)) {
            if (strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' ||
                strchr(header + 7, ' ') != NULL)
                return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
            auth_result = pm3000_authorize(
                configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
                header + 7, "control", outlet_id, &authorization, error, sizeof(error));
            if (auth_result < 0) return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
            if (!authorization.authenticated) return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
            if (!authorization.authorized) return cgi_error(403U, "Forbidden", "forbidden", "Token does not authorize this outlet action.");
            auth_result = service_apply_outlet_action(
                configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                outlet_id, revision, action, error, sizeof(error));
        } else {
            if (load_request_session(
                    configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                    1, &gui_session) != 0)
                return cgi_error(401U, "Unauthorized", "unauthorized",
                                 "Session or Bearer authentication required.");
            if (!gui_session.can_control_power)
                return cgi_error(403U, "Forbidden", "forbidden", "Power control is not permitted.");
            if (!pm3000_session_csrf_matches(&gui_session, getenv("HTTP_X_CSRF_TOKEN")))
                return cgi_error(403U, "Forbidden", "csrf_rejected", "CSRF token rejected.");
            auth_result = pm3000_apply_outlet_action_session(
                configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
                gui_session.sid, outlet_id, revision, action, error, sizeof(error));
        }
        if (auth_result == 1) return cgi_error(404U, "Not Found", "not_found", "Outlet not found.");
        if (auth_result == 2) return cgi_error(409U, "Conflict", "inventory_changed", "Refresh the outlet inventory and retry.");
        if (auth_result == 3) return cgi_error(503U, "Service Unavailable", "action_outcome_unknown", "The outlet action may have been dispatched; do not retry automatically.");
        if (auth_result != 0)
            return cgi_service_backend_error(error, "Outlet action was not confirmed.");
        cgi_headers(204U, "No Content");
        return ferror(stdout) ? 1 : 0;
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
    if (!browser_session_authorization(header)) {
        if (strncmp(header, "Bearer ", 7U) != 0 || header[7] == '\0' ||
            strchr(header + 7, ' ') != NULL)
            return cgi_error(401U, "Unauthorized", "unauthorized", "Bearer authentication required.");
        token = header + 7;
        auth_result = pm3000_authorize(
            configured_path("PM3000_TOKEN_STORE", "/mnt/hdUser/pm3000-revive/rest/tokens.json"),
            token, "read", detail_request ? requested_outlet : NULL,
            &authorization, error, sizeof(error));
        if (auth_result < 0)
            return cgi_error(503U, "Service Unavailable", "token_store_unavailable", "Authentication store unavailable.");
        if (!authorization.authenticated)
            return cgi_error(401U, "Unauthorized", "unauthorized", "Token rejected.");
        if (!authorization.authorized)
            return cgi_error(403U, "Forbidden", "forbidden", "Token does not authorize this outlet.");
    } else {
        if (load_request_session(
                configured_path("PM3000_SESSION_DIR", "/tmp/pm3000-modern-sessions"),
                1, &gui_session) != 0)
            return cgi_error(401U, "Unauthorized", "unauthorized",
                             "Session or Bearer authentication required.");
        memset(&authorization, 0, sizeof(authorization));
        authorization.authenticated = 1;
        authorization.authorized = 1;
        authorization.unrestricted = 1;
        using_session = 1;
    }
    if ((using_session ?
         pm3000_fetch_topology_session(
             configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
             gui_session.sid, &response, &response_length, error, sizeof(error)) :
         service_fetch_topology(
             configured_path("PM3000_AVTRANS_SOCKET", "/dev/avtrans_socket"),
             &response, &response_length, error, sizeof(error))) != 0) {
        free(response);
        fprintf(stderr, "pm3000-rest: outlet topology fetch failed via %s: %s\n",
                using_session ? "browser session" : "local service session",
                error[0] != '\0' ? error : "unspecified backend error");
        if (!using_session)
            return cgi_service_backend_error(error, "Read-only backend unavailable.");
        return cgi_error(503U, "Service Unavailable", "backend_unavailable",
                         "Read-only backend unavailable.");
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

static int diagnose_backend(const char *socket_path) {
    unsigned char *response = NULL;
    size_t response_length = 0;
    char error[160] = {0};
    const char *phase = "backend";
    int result;
    if (getenv("REMOTE_ADDR") == NULL && setenv("REMOTE_ADDR", "127.0.0.1", 1) != 0) {
        fputs("backend_phase=environment\n", stdout);
        return 3;
    }
    result = service_fetch_topology(socket_path, &response,
                                    &response_length, error, sizeof(error));
    free(response);
    if (result == 0) {
        fputs("backend_phase=complete\n", stdout);
        return 0;
    }
    if (strcmp(error, "service identity missing") == 0) phase = "service_user";
    else if (strncmp(error, "service session", 15U) == 0) phase = "session";
    else if (strcmp(error, "controller unavailable") == 0 ||
             strcmp(error, "controller response rejected") == 0) phase = "topology";
    printf("backend_phase=%s\n", phase);
    return 3;
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
    if (argc == 3 && strcmp(argv[1], "--diagnose-backend") == 0)
        return diagnose_backend(argv[2]);
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
    if (argc == 2 && strcmp(argv[1], "--diagnose-backend") == 0)
        return diagnose_backend("/dev/avtrans_socket");
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
    fputs("usage: pm3000-rest --diagnose-backend | --derive outlet|pdu ID | --revision ID... | --project FILE\n", stderr);
    return 2;
}
