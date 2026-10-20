#ifndef PM3000_IDENTIFIERS_H
#define PM3000_IDENTIFIERS_H

#include <stddef.h>

#define PM3000_ID_LENGTH 22U

int pm3000_derive_id(const char *kind, const char *identity,
                     char output[PM3000_ID_LENGTH + 1U]);
int pm3000_inventory_revision(char **identities, size_t count,
                              char output[PM3000_ID_LENGTH + 1U]);

#endif
