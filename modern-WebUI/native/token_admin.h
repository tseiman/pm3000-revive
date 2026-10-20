#ifndef PM3000_TOKEN_ADMIN_H
#define PM3000_TOKEN_ADMIN_H

#include <stddef.h>

typedef enum {
    PM3000_TOKEN_OK = 0,
    PM3000_TOKEN_AUTH = 1,
    PM3000_TOKEN_BAD_REQUEST = 2,
    PM3000_TOKEN_NOT_FOUND = 3,
    PM3000_TOKEN_LAST_ADMIN = 4,
    PM3000_TOKEN_LIMIT = 5,
    PM3000_TOKEN_STORE_ERROR = 6,
    PM3000_TOKEN_DELIVERY_ERROR = 7,
    PM3000_TOKEN_RESPONSE_SENT_ERROR = 8,
    PM3000_TOKEN_COMMITTED_UNCERTAIN = 9
} pm3000_token_result;

typedef int (*pm3000_token_delivery)(const char *response, void *context);

pm3000_token_result pm3000_token_list(const char *store_path, const char *administrator,
                                       char **response);
pm3000_token_result pm3000_token_create(const char *store_path, const char *administrator,
                                         const unsigned char *body, size_t body_length,
                                         pm3000_token_delivery deliver, void *context);
pm3000_token_result pm3000_token_set_enabled(const char *store_path, const char *administrator,
                                              const char *token_id, int enabled);
pm3000_token_result pm3000_token_revoke(const char *store_path, const char *administrator,
                                         const char *token_id);

#endif
