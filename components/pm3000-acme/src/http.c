#include "pm3000_acme_http.h"

#include <limits.h>

static char lower_ascii(char value)
{
    if (value >= 'A' && value <= 'Z') return (char)(value + ('a' - 'A'));
    return value;
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

static int span_equal_ci(const unsigned char *data, unsigned int length,
                         const char *text)
{
    unsigned int index = 0U;
    while (index < length && text[index] != '\0') {
        if (lower_ascii((char)data[index]) != lower_ascii(text[index])) return 0;
        ++index;
    }
    return index == length && text[index] == '\0';
}

static int append_byte(char *output, unsigned int capacity,
                       unsigned int *used, char value)
{
    if (*used + 1U >= capacity) return PM3000_ACME_HTTP_LIMIT;
    output[(*used)++] = value;
    output[*used] = '\0';
    return PM3000_ACME_HTTP_OK;
}

static int append_text(char *output, unsigned int capacity,
                       unsigned int *used, const char *text)
{
    unsigned int index = 0U;
    while (text[index] != '\0') {
        if (append_byte(output, capacity, used, text[index]) !=
            PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_LIMIT;
        ++index;
    }
    return PM3000_ACME_HTTP_OK;
}

static int append_unsigned(char *output, unsigned int capacity,
                           unsigned int *used, unsigned int value)
{
    char reversed[10];
    unsigned int count = 0U;
    do {
        reversed[count++] = (char)('0' + value % 10U);
        value /= 10U;
    } while (value != 0U && count < sizeof(reversed));
    while (count != 0U) {
        if (append_byte(output, capacity, used, reversed[--count]) !=
            PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_LIMIT;
    }
    return PM3000_ACME_HTTP_OK;
}

static int valid_method(const char *method)
{
    return text_equal(method, "GET") || text_equal(method, "HEAD") ||
           text_equal(method, "POST");
}

int pm3000_acme_http_build_request(
    const char *method, const struct pm3000_acme_url *url,
    const char *content_type, const unsigned char *body,
    unsigned int body_length, char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    unsigned int used = 0U;
    unsigned int index;
    if (output_length != (unsigned int *)0) *output_length = 0U;
    if (method == (const char *)0 || url == (const struct pm3000_acme_url *)0 ||
        output == (char *)0 || output_capacity == 0U ||
        output_length == (unsigned int *)0 || !valid_method(method) ||
        url->host[0] == '\0' || url->path[0] != '/' ||
        body_length > PM3000_ACME_HTTP_BODY_MAX ||
        (body_length != 0U && body == (const unsigned char *)0) ||
        (body_length != 0U && content_type == (const char *)0)) {
        return PM3000_ACME_HTTP_INVALID;
    }
    output[0] = '\0';
#define APPEND_TEXT(value) do { \
    if (append_text(output, output_capacity, &used, (value)) != \
        PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_LIMIT; \
} while (0)
    APPEND_TEXT(method);
    APPEND_TEXT(" ");
    APPEND_TEXT(url->path);
    APPEND_TEXT(" HTTP/1.1\r\nHost: ");
    APPEND_TEXT(url->host);
    if (url->port != 443U) {
        APPEND_TEXT(":");
        if (append_unsigned(output, output_capacity, &used, url->port) !=
            PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_LIMIT;
    }
    APPEND_TEXT("\r\nUser-Agent: pm3000-acme/1\r\nAccept: application/json\r\n");
    if (body_length != 0U) {
        APPEND_TEXT("Content-Type: ");
        APPEND_TEXT(content_type);
        APPEND_TEXT("\r\nContent-Length: ");
        if (append_unsigned(output, output_capacity, &used, body_length) !=
            PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_LIMIT;
        APPEND_TEXT("\r\n");
    }
    APPEND_TEXT("Connection: close\r\n\r\n");
#undef APPEND_TEXT
    if (used + body_length >= output_capacity) return PM3000_ACME_HTTP_LIMIT;
    for (index = 0U; index < body_length; ++index)
        output[used + index] = (char)body[index];
    used += body_length;
    output[used] = '\0';
    *output_length = used;
    return PM3000_ACME_HTTP_OK;
}

static void clear_response(struct pm3000_acme_http_response *response)
{
    response->status_code = 0U;
    response->replay_nonce[0] = '\0';
    response->location[0] = '\0';
    response->content_type[0] = '\0';
    response->body_length = 0U;
}

static int copy_span(char *output, unsigned int capacity,
                     const unsigned char *input, unsigned int length)
{
    unsigned int index;
    if (length + 1U > capacity) return PM3000_ACME_HTTP_LIMIT;
    for (index = 0U; index < length; ++index) {
        if (input[index] < 0x20U || input[index] > 0x7eU)
            return PM3000_ACME_HTTP_INVALID;
        output[index] = (char)input[index];
    }
    output[length] = '\0';
    return PM3000_ACME_HTTP_OK;
}

static int valid_nonce(const char *nonce)
{
    unsigned int index = 0U;
    while (nonce[index] != '\0') {
        char value = nonce[index];
        if (!((value >= 'A' && value <= 'Z') ||
              (value >= 'a' && value <= 'z') ||
              (value >= '0' && value <= '9') || value == '-' || value == '_'))
            return 0;
        ++index;
    }
    return index != 0U && index <= PM3000_ACME_HTTP_NONCE_MAX;
}

static int parse_decimal(const unsigned char *data, unsigned int length,
                         unsigned int *value)
{
    unsigned int result = 0U;
    unsigned int index;
    if (length == 0U) return 0;
    for (index = 0U; index < length; ++index) {
        unsigned int digit;
        if (data[index] < '0' || data[index] > '9') return 0;
        digit = (unsigned int)(data[index] - '0');
        if (result > (UINT_MAX - digit) / 10U) return 0;
        result = result * 10U + digit;
    }
    *value = result;
    return 1;
}

static int decode_chunked(const unsigned char *input, unsigned int length,
                          unsigned char *output, unsigned int capacity,
                          unsigned int *output_length)
{
    unsigned int offset = 0U;
    unsigned int used = 0U;
    while (offset < length) {
        unsigned int size = 0U;
        unsigned int digits = 0U;
        unsigned int index;
        while (offset < length && input[offset] != '\r') {
            unsigned int value;
            unsigned char byte = input[offset++];
            if (byte >= '0' && byte <= '9') value = byte - '0';
            else if (byte >= 'a' && byte <= 'f') value = byte - 'a' + 10U;
            else if (byte >= 'A' && byte <= 'F') value = byte - 'A' + 10U;
            else return PM3000_ACME_HTTP_INVALID;
            if (++digits > 8U || size > (PM3000_ACME_HTTP_BODY_MAX - value) / 16U)
                return PM3000_ACME_HTTP_LIMIT;
            size = size * 16U + value;
        }
        if (digits == 0U || offset + 1U >= length || input[offset] != '\r' ||
            input[offset + 1U] != '\n') return PM3000_ACME_HTTP_INVALID;
        offset += 2U;
        if (size == 0U) {
            if (offset + 2U != length || input[offset] != '\r' ||
                input[offset + 1U] != '\n') return PM3000_ACME_HTTP_INVALID;
            *output_length = used;
            if (used < capacity) output[used] = '\0';
            return PM3000_ACME_HTTP_OK;
        }
        if (size > length - offset || used + size > PM3000_ACME_HTTP_BODY_MAX ||
            used + size >= capacity) return PM3000_ACME_HTTP_LIMIT;
        for (index = 0U; index < size; ++index)
            output[used + index] = input[offset + index];
        used += size;
        offset += size;
        if (offset + 1U >= length || input[offset] != '\r' ||
            input[offset + 1U] != '\n') return PM3000_ACME_HTTP_INVALID;
        offset += 2U;
    }
    return PM3000_ACME_HTTP_INVALID;
}

int pm3000_acme_http_parse_response(
    const char *method, const unsigned char *input, unsigned int input_length,
    const struct pm3000_acme_url *origin,
    struct pm3000_acme_http_response *response,
    unsigned char *body, unsigned int body_capacity)
{
    unsigned int header_end = 0U;
    unsigned int line_end;
    unsigned int offset;
    unsigned int content_length = 0U;
    int have_content_length = 0;
    int have_transfer_encoding = 0;
    int have_nonce = 0;
    int have_location = 0;
    int have_content_type = 0;
    if (method == (const char *)0 || !valid_method(method) ||
        input == (const unsigned char *)0 ||
        response == (struct pm3000_acme_http_response *)0 ||
        body == (unsigned char *)0 || body_capacity == 0U ||
        input_length > PM3000_ACME_HTTP_HEADER_MAX +
                       PM3000_ACME_HTTP_BODY_MAX + 32U) {
        return PM3000_ACME_HTTP_INVALID;
    }
    clear_response(response);
    for (offset = 0U; offset + 3U < input_length &&
                      offset + 4U <= PM3000_ACME_HTTP_HEADER_MAX; ++offset) {
        if (input[offset] == '\r' && input[offset + 1U] == '\n' &&
            input[offset + 2U] == '\r' && input[offset + 3U] == '\n') {
            header_end = offset + 4U;
            break;
        }
    }
    if (header_end == 0U) return PM3000_ACME_HTTP_INVALID;
    line_end = 0U;
    while (line_end + 1U < header_end &&
           !(input[line_end] == '\r' && input[line_end + 1U] == '\n'))
        ++line_end;
    if (line_end < 12U || !span_equal_ci(input, 9U, "HTTP/1.1 ") ||
        input[9] < '1' || input[9] > '5' ||
        input[10] < '0' || input[10] > '9' ||
        input[11] < '0' || input[11] > '9' ||
        (line_end > 12U && input[12] != ' ')) return PM3000_ACME_HTTP_INVALID;
    response->status_code = (unsigned int)(input[9] - '0') * 100U +
                            (unsigned int)(input[10] - '0') * 10U +
                            (unsigned int)(input[11] - '0');
    offset = line_end + 2U;
    while (offset + 2U < header_end) {
        unsigned int name_start = offset;
        unsigned int name_length;
        unsigned int value_start;
        unsigned int value_end;
        struct pm3000_acme_url location_url;
        if (input[offset] == ' ' || input[offset] == '\t')
            return PM3000_ACME_HTTP_INVALID;
        while (offset < header_end && input[offset] != ':' &&
               input[offset] != '\r' && input[offset] != '\n') ++offset;
        if (offset >= header_end || input[offset] != ':' || offset == name_start)
            return PM3000_ACME_HTTP_INVALID;
        name_length = offset - name_start;
        ++offset;
        while (offset < header_end &&
               (input[offset] == ' ' || input[offset] == '\t')) ++offset;
        value_start = offset;
        while (offset + 1U < header_end &&
               !(input[offset] == '\r' && input[offset + 1U] == '\n')) {
            if ((input[offset] < 0x20U && input[offset] != '\t') ||
                input[offset] > 0x7eU) return PM3000_ACME_HTTP_INVALID;
            ++offset;
        }
        if (offset + 1U >= header_end) return PM3000_ACME_HTTP_INVALID;
        value_end = offset;
        while (value_end > value_start &&
               (input[value_end - 1U] == ' ' || input[value_end - 1U] == '\t'))
            --value_end;
        offset += 2U;
        if (span_equal_ci(input + name_start, name_length, "content-length")) {
            if (have_content_length ||
                !parse_decimal(input + value_start, value_end - value_start,
                               &content_length)) return PM3000_ACME_HTTP_INVALID;
            have_content_length = 1;
        } else if (span_equal_ci(input + name_start, name_length,
                                 "transfer-encoding")) {
            if (have_transfer_encoding ||
                !span_equal_ci(input + value_start, value_end - value_start,
                               "chunked")) return PM3000_ACME_HTTP_INVALID;
            have_transfer_encoding = 1;
        } else if (span_equal_ci(input + name_start, name_length,
                                 "replay-nonce")) {
            if (have_nonce || copy_span(response->replay_nonce,
                                        sizeof(response->replay_nonce),
                                        input + value_start,
                                        value_end - value_start) !=
                                  PM3000_ACME_HTTP_OK ||
                !valid_nonce(response->replay_nonce))
                return PM3000_ACME_HTTP_INVALID;
            have_nonce = 1;
        } else if (span_equal_ci(input + name_start, name_length, "location")) {
            if (have_location || copy_span(response->location,
                                           sizeof(response->location),
                                           input + value_start,
                                           value_end - value_start) !=
                                     PM3000_ACME_HTTP_OK ||
                pm3000_acme_url_parse(response->location, &location_url) !=
                    PM3000_ACME_URL_OK ||
                (origin != (const struct pm3000_acme_url *)0 &&
                 !pm3000_acme_url_same_origin(origin, &location_url)))
                return PM3000_ACME_HTTP_INVALID;
            have_location = 1;
        } else if (span_equal_ci(input + name_start, name_length,
                                 "content-type")) {
            if (have_content_type || copy_span(
                    response->content_type, sizeof(response->content_type),
                    input + value_start, value_end - value_start) !=
                    PM3000_ACME_HTTP_OK) return PM3000_ACME_HTTP_INVALID;
            have_content_type = 1;
        }
    }
    if (have_content_length && have_transfer_encoding)
        return PM3000_ACME_HTTP_INVALID;
    if (text_equal(method, "HEAD")) {
        if (input_length != header_end) return PM3000_ACME_HTTP_INVALID;
        body[0] = '\0';
        response->body_length = 0U;
        return PM3000_ACME_HTTP_OK;
    }
    if (have_transfer_encoding)
        return decode_chunked(input + header_end, input_length - header_end,
                              body, body_capacity, &response->body_length);
    if (have_content_length) {
        unsigned int index;
        if (content_length != input_length - header_end ||
            content_length > PM3000_ACME_HTTP_BODY_MAX ||
            content_length >= body_capacity) return PM3000_ACME_HTTP_LIMIT;
        for (index = 0U; index < content_length; ++index)
            body[index] = input[header_end + index];
        body[content_length] = '\0';
        response->body_length = content_length;
        return PM3000_ACME_HTTP_OK;
    }
    if (input_length - header_end > PM3000_ACME_HTTP_BODY_MAX ||
        input_length - header_end >= body_capacity) return PM3000_ACME_HTTP_LIMIT;
    for (offset = header_end; offset < input_length; ++offset)
        body[offset - header_end] = input[offset];
    response->body_length = input_length - header_end;
    body[response->body_length] = '\0';
    return PM3000_ACME_HTTP_OK;
}
