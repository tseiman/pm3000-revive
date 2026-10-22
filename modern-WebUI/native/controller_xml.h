#ifndef PM3000_CONTROLLER_XML_H
#define PM3000_CONTROLLER_XML_H

#include <stddef.h>
#include <stdint.h>

int pm3000_xml_login_sid(const unsigned char *xml, size_t length,
                         char sid[129]);
int pm3000_xml_navigation(const unsigned char *xml, size_t length,
                          const char *const *allowed_paths,
                          unsigned int allowed_count, uint64_t *path_mask,
                          int *can_manage, int *can_help_language,
                          int *can_data_buffering,
                          int *can_appliance_logging,
                          int *can_time_zone);
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

#define PM3000_FIXED_MAX_FIELDS 16U
#define PM3000_FIXED_MAX_CHOICES 569U
#define PM3000_FIXED_VALUE_SIZE 257U

struct pm3000_xml_fixed_field {
    const char *id;
    const char *structure;
    const char *parent_id;
    const char *parent_structure;
};

struct pm3000_xml_fixed_parameter {
    const char *id;
    const char *structure;
    const char *parent_id;
    const char *parent_structure;
};

struct pm3000_xml_fixed_result {
    char values[PM3000_FIXED_MAX_FIELDS][PM3000_FIXED_VALUE_SIZE];
    char choices[PM3000_FIXED_MAX_CHOICES][33];
    unsigned char choice_fields[PM3000_FIXED_MAX_CHOICES];
    unsigned int choice_count;
};

int pm3000_xml_fixed_form(const unsigned char *xml, size_t length,
                          const char *path, const char *form,
                          const struct pm3000_xml_fixed_field *fields,
                          unsigned int field_count,
                          const struct pm3000_xml_fixed_parameter *parameters,
                          unsigned int parameter_count, uint32_t choice_field_mask,
                          struct pm3000_xml_fixed_result *out);

struct pm3000_sysinfo {
    char model_number[256];
    char boot_code_version[256];
    char firmware_version[256];
    char booted_from[256];
    char cpu[256];
    char revision[256];
    char bogomips[256];
};

int pm3000_xml_system_information(const unsigned char *xml, size_t length,
                                   struct pm3000_sysinfo *out);

#define PM3000_MAX_TABLE_ROWS 25U

struct pm3000_memory_row {
    char name[256];
    char value[256];
};

struct pm3000_memory_table {
    struct pm3000_memory_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_memory_table(const unsigned char *xml, size_t length,
                             struct pm3000_memory_table *out);

struct pm3000_flash_row {
    char filesystem[256];
    char blocks1k[256];
    char used[256];
    char available[256];
    char use_percentage[256];
    char mounted_on[256];
};

struct pm3000_flash_table {
    struct pm3000_flash_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_flash_table(const unsigned char *xml, size_t length,
                            struct pm3000_flash_table *out);

struct pm3000_netdev_row {
    char device_name[256];
    char status[256];
    char ipv4_address[256];
    char ipv4_mask[256];
    char ipv6_address[256];
};

struct pm3000_netdev_table {
    struct pm3000_netdev_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_netdev_table(const unsigned char *xml, size_t length,
                             struct pm3000_netdev_table *out);

struct pm3000_route4_row {
    char destination[256];
    char gateway[256];
    char genmask[256];
    char flags[256];
    char metric[256];
    char ref[256];
    char use[256];
    char iface[256];
};

struct pm3000_route4_table {
    struct pm3000_route4_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_route4_table(const unsigned char *xml, size_t length,
                             struct pm3000_route4_table *out);

struct pm3000_route6_row {
    char destination[256];
    char next_hop[256];
    char flags[256];
    char metric[256];
    char ref[256];
    char use[256];
    char iface[256];
};

struct pm3000_route6_table {
    struct pm3000_route6_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_route6_table(const unsigned char *xml, size_t length,
                             struct pm3000_route6_table *out);

struct pm3000_serial_row {
    char device_name[256];
    char port_profile[256];
    char speed[256];
    char signals[256];
    char tx_bytes[256];
    char rx_bytes[256];
    char frame_error[256];
    char parity_error[256];
    char brk[256];
    char overrun[256];
};

struct pm3000_serial_table {
    struct pm3000_serial_row rows[PM3000_MAX_TABLE_ROWS];
    unsigned int row_count;
};

int pm3000_xml_serial_table(const unsigned char *xml, size_t length,
                              struct pm3000_serial_table *out);

#endif
