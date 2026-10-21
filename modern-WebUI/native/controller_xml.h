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
int pm3000_xml_content_result(const unsigned char *xml, size_t length,
                              const char *path);
int pm3000_xml_password_changed(const unsigned char *xml, size_t length);
int pm3000_xml_form_value(const unsigned char *xml, size_t length,
                           const char *path, const char *form,
                           const char *parameter, char *value,
                           size_t value_size);
int pm3000_xml_boolean_form_value(const unsigned char *xml, size_t length,
                                  const char *path, const char *form,
                                  const char *parameter, int *value);
int pm3000_xml_dsview_value(const unsigned char *xml, size_t length,
                            const char *path, int *value);
int pm3000_xml_nis_values(const unsigned char *xml, size_t length,
                          const char *path, char *domain, size_t domain_size,
                          char *address, size_t address_size);

#endif
