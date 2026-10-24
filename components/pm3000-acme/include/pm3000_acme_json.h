#ifndef PM3000_ACME_JSON_H
#define PM3000_ACME_JSON_H

#define PM3000_ACME_JSON_MAX_BYTES 32768U
#define PM3000_ACME_JSON_MAX_TOKENS 256U
#define PM3000_ACME_JSON_MAX_DEPTH 8U
#define PM3000_ACME_JSON_MAX_MEMBERS 32U
#define PM3000_ACME_JSON_KEY_MAX 63U

enum pm3000_acme_json_result {
    PM3000_ACME_JSON_OK = 0,
    PM3000_ACME_JSON_INVALID = -1,
    PM3000_ACME_JSON_LIMIT = -2,
    PM3000_ACME_JSON_NOT_FOUND = -3,
    PM3000_ACME_JSON_TYPE = -4,
    PM3000_ACME_JSON_OUTPUT_TOO_SMALL = -5
};

enum pm3000_acme_json_type {
    PM3000_ACME_JSON_OBJECT = 1,
    PM3000_ACME_JSON_ARRAY = 2,
    PM3000_ACME_JSON_STRING = 3,
    PM3000_ACME_JSON_NUMBER = 4,
    PM3000_ACME_JSON_TRUE = 5,
    PM3000_ACME_JSON_FALSE = 6,
    PM3000_ACME_JSON_NULL = 7
};

struct pm3000_acme_json_token {
    unsigned int start;
    unsigned int end;
    int parent;
    unsigned int count;
    unsigned char type;
};

struct pm3000_acme_json_document {
    const unsigned char *data;
    unsigned int length;
    unsigned int token_count;
    struct pm3000_acme_json_token tokens[PM3000_ACME_JSON_MAX_TOKENS];
};

int pm3000_acme_json_parse(const unsigned char *data, unsigned int length,
                           struct pm3000_acme_json_document *document);
int pm3000_acme_json_object_get(const struct pm3000_acme_json_document *document,
                                int object_token, const char *key,
                                int *value_token);
int pm3000_acme_json_array_length(const struct pm3000_acme_json_document *document,
                                  int array_token, unsigned int *length);
int pm3000_acme_json_array_get(const struct pm3000_acme_json_document *document,
                               int array_token, unsigned int index,
                               int *value_token);
int pm3000_acme_json_string_copy(const struct pm3000_acme_json_document *document,
                                 int string_token, char *output,
                                 unsigned int output_capacity);

#endif
