#ifndef PM3000_FIXED_FORM_H
#define PM3000_FIXED_FORM_H

#include <stddef.h>

#include "controller_xml.h"

typedef enum {
    PM3000_FORM_HELP_LANGUAGE = 1,
    PM3000_FORM_DATA_BUFFERING = 2,
    PM3000_FORM_APPLIANCE_LOGGING = 3,
    PM3000_FORM_TIME_ZONE = 4
} pm3000_fixed_form_kind;

struct pm3000_fixed_snapshot {
    struct pm3000_xml_fixed_result form;
    char revision[67];
};

struct pm3000_fixed_input {
    char values[PM3000_FIXED_MAX_FIELDS][PM3000_FIXED_VALUE_SIZE];
    unsigned char present[PM3000_FIXED_MAX_FIELDS];
};

const char *pm3000_fixed_path(pm3000_fixed_form_kind kind);
unsigned int pm3000_fixed_field_count(pm3000_fixed_form_kind kind);
int pm3000_fixed_parse_backend(pm3000_fixed_form_kind kind,
                               const unsigned char *xml, size_t length,
                               struct pm3000_fixed_snapshot *out);
int pm3000_fixed_parse_request(pm3000_fixed_form_kind kind,
                               const unsigned char *json, size_t length,
                               struct pm3000_fixed_input *out);
int pm3000_fixed_language_allowed(const struct pm3000_fixed_snapshot *snapshot,
                                   const char *language);
int pm3000_fixed_values_match(pm3000_fixed_form_kind kind,
                              const struct pm3000_fixed_snapshot *snapshot,
                              const struct pm3000_fixed_input *input);
int pm3000_fixed_merge_inactive(pm3000_fixed_form_kind kind,
                                const struct pm3000_fixed_snapshot *snapshot,
                                struct pm3000_fixed_input *input);
int pm3000_fixed_serialize(pm3000_fixed_form_kind kind,
                           const struct pm3000_fixed_input *input,
                           char *output, size_t capacity);

#endif
