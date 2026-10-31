#include "pm3000_acme_config.h"

#include <stdio.h>
#include <string.h>

int main(void)
{
    static const char valid[] =
        "{\"enabled\":true,\"directory_url\":\"https://acme.example.test/directory\","
        "\"ca_file\":\"/etc/CA/acme-root.pem\","
        "\"dns_names\":[\"PDU1.TSEI.MDN\",\"usv3.tsei.mdn\"]}";
    static const char canonical[] =
        "{\"enabled\":true,\"directory_url\":\"https://acme.example.test/directory\","
        "\"ca_file\":\"/etc/CA/acme-root.pem\","
        "\"dns_names\":[\"pdu1.tsei.mdn\",\"usv3.tsei.mdn\"]}\n";
    struct pm3000_acme_runtime_config config;
    unsigned char serialized[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
    unsigned int serialized_length = 0U;
    if (pm3000_acme_config_parse((const unsigned char *)valid,
                                 sizeof(valid) - 1U, &config) !=
            PM3000_ACME_CONFIG_OK || !config.enabled ||
        strcmp(config.directory_url,
               "https://acme.example.test/directory") != 0 ||
        strcmp(config.ca_file, "/etc/CA/acme-root.pem") != 0 ||
        config.dns_name_count != 2U ||
        strcmp(config.dns_names[0], "pdu1.tsei.mdn") != 0) {
        fprintf(stderr, "valid config rejected\n");
        return 1;
    }
    if (pm3000_acme_config_serialize(&config, serialized,
                                     sizeof(serialized),
                                     &serialized_length) !=
            PM3000_ACME_CONFIG_OK ||
        serialized_length != sizeof(canonical) - 1U ||
        memcmp(serialized, canonical, serialized_length) != 0 ||
        pm3000_acme_config_parse(serialized, serialized_length, &config) !=
            PM3000_ACME_CONFIG_OK) {
        fprintf(stderr, "canonical config serialization failed\n");
        return 1;
    }
#define REJECT(value) do { \
    static const char sample[] = value; \
    if (pm3000_acme_config_parse((const unsigned char *)sample, \
            sizeof(sample) - 1U, &config) == PM3000_ACME_CONFIG_OK) { \
        fprintf(stderr, "invalid config accepted: %s\n", sample); \
        return 1; \
    } \
} while (0)
    REJECT("{\"enabled\":true,\"directory_url\":\"http://bad/d\","
           "\"ca_file\":\"/ca\",\"dns_names\":[\"pdu\"]}");
    REJECT("{\"enabled\":true,\"directory_url\":\"https://ok/d\","
           "\"ca_file\":\"relative\",\"dns_names\":[\"pdu\"]}");
    REJECT("{\"enabled\":true,\"directory_url\":\"https://ok/d\","
           "\"ca_file\":\"/ca\",\"dns_names\":[\"pdu\",\"PDU\"]}");
    REJECT("{\"enabled\":true,\"directory_url\":\"https://ok/d\","
           "\"ca_file\":\"/ca\",\"dns_names\":[\"pdu\"],\"extra\":1}");
#undef REJECT
    puts("config.tests.complete=yes");
    return 0;
}
