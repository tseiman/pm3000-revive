#ifndef PM3000_CONTROLLER_XML_H
#define PM3000_CONTROLLER_XML_H

#include <stddef.h>
#include <stdint.h>

int pm3000_xml_login_sid(const unsigned char *xml, size_t length,
                         char sid[129]);
int pm3000_xml_navigation(const unsigned char *xml, size_t length,
                          const char *const *allowed_paths,
                          unsigned int allowed_count, uint64_t *path_mask,
                          int *can_manage);
int pm3000_xml_topology_controls(const unsigned char *xml, size_t length,
                                 int *can_control);
int pm3000_xml_confirm(const unsigned char *xml, size_t length,
                       const char *action, const char *path);

#endif
