#include "pm3000_acme_base64url.h"

static const char alphabet[] =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";

int pm3000_acme_base64url_encode(const unsigned char *input,
                                  unsigned int input_length,
                                  char *output,
                                  unsigned int output_capacity)
{
    unsigned int groups;
    unsigned int remainder;
    unsigned int required;
    unsigned int input_index = 0U;
    unsigned int output_index = 0U;

    if (output == (char *)0 || output_capacity == 0U ||
        input == (const unsigned char *)0) {
        return PM3000_ACME_BASE64URL_INVALID;
    }
    output[0] = '\0';
    groups = input_length / 3U;
    remainder = input_length % 3U;
    if (groups > (~0U - 4U) / 4U) {
        return PM3000_ACME_BASE64URL_INVALID;
    }
    required = groups * 4U;
    if (remainder != 0U) required += remainder + 1U;
    if (required >= output_capacity) {
        return PM3000_ACME_BASE64URL_OUTPUT_TOO_SMALL;
    }

    while (input_index + 3U <= input_length) {
        unsigned int value = ((unsigned int)input[input_index] << 16) |
                             ((unsigned int)input[input_index + 1U] << 8) |
                             (unsigned int)input[input_index + 2U];
        output[output_index++] = alphabet[(value >> 18) & 63U];
        output[output_index++] = alphabet[(value >> 12) & 63U];
        output[output_index++] = alphabet[(value >> 6) & 63U];
        output[output_index++] = alphabet[value & 63U];
        input_index += 3U;
    }
    if (remainder == 1U) {
        unsigned int value = (unsigned int)input[input_index] << 16;
        output[output_index++] = alphabet[(value >> 18) & 63U];
        output[output_index++] = alphabet[(value >> 12) & 63U];
    } else if (remainder == 2U) {
        unsigned int value = ((unsigned int)input[input_index] << 16) |
                             ((unsigned int)input[input_index + 1U] << 8);
        output[output_index++] = alphabet[(value >> 18) & 63U];
        output[output_index++] = alphabet[(value >> 12) & 63U];
        output[output_index++] = alphabet[(value >> 6) & 63U];
    }
    output[output_index] = '\0';
    return PM3000_ACME_BASE64URL_OK;
}
