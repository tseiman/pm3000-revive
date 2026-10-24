#ifndef PM3000_ACME_BASE64URL_H
#define PM3000_ACME_BASE64URL_H

enum pm3000_acme_base64url_result {
    PM3000_ACME_BASE64URL_OK = 0,
    PM3000_ACME_BASE64URL_INVALID = -1,
    PM3000_ACME_BASE64URL_OUTPUT_TOO_SMALL = -2
};

int pm3000_acme_base64url_encode(const unsigned char *input,
                                  unsigned int input_length,
                                  char *output,
                                  unsigned int output_capacity);

#endif
