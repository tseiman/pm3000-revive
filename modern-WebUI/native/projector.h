#ifndef PM3000_PROJECTOR_H
#define PM3000_PROJECTOR_H

#include <stdio.h>

int pm3000_project_file(const char *path, FILE *output, char *error, unsigned int error_size);
int pm3000_project_detail_bytes(const unsigned char *xml, unsigned long length,
                                const char *outlet_id, FILE *output,
                                char *error, unsigned int error_size);
int pm3000_project_detail_file(const char *path, const char *outlet_id, FILE *output,
                               char *error, unsigned int error_size);
int pm3000_project_bytes(const unsigned char *xml, unsigned long length, FILE *output,
                          char *error, unsigned int error_size);
int pm3000_project_bytes_filtered(const unsigned char *xml, unsigned long length, FILE *output,
                                  int unrestricted,
                                  const char *outlets, unsigned int outlet_count,
                                  char *error, unsigned int error_size);

#endif
