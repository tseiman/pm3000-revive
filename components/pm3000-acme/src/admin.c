#define _GNU_SOURCE

#include "pm3000_acme_admin.h"
#include "pm3000_acme_certificate.h"
#include "pm3000_acme_crypto.h"
#include "pm3000_acme_state.h"
#include "pm3000_acme_store.h"
#include "stat_compat.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

static unsigned char config_buffer[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
static unsigned char config_read_buffer[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
static unsigned char verify_buffer[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
static unsigned char ca_verify_buffer[PM3000_ACME_CA_BUNDLE_MAX + 1U];
static unsigned char revision_buffer[PM3000_ACME_CONFIG_MAX_BYTES +
                                     PM3000_ACME_CA_BUNDLE_MAX + 1U];

/* 1 means absent, 0 means a real entry exists, -1 means unsafe/unknown. */
static int entry_absent_at(int directory_fd, const char *name)
{
    int descriptor = openat(directory_fd, name,
                            O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    if (descriptor >= 0) {
        close(descriptor);
        return 0;
    }
    return errno == ENOENT ? 1 : -1;
}

static int read_config(int root_fd, struct pm3000_acme_runtime_config *config)
{
    unsigned int length = 0U;
    int result = pm3000_acme_store_read_at(
        root_fd, "config.json", config_read_buffer, PM3000_ACME_CONFIG_MAX_BYTES,
        &length, 1);
    if (result != PM3000_ACME_STORE_OK) {
        int absent = entry_absent_at(root_fd, "config.json");
        return absent == 1 ? PM3000_ACME_ADMIN_NOT_FOUND
                           : PM3000_ACME_ADMIN_UNSAFE;
    }
    if (length == 0U ||
        length > PM3000_ACME_CONFIG_MAX_BYTES)
        return PM3000_ACME_ADMIN_UNSAFE;
    return pm3000_acme_config_parse(config_read_buffer, length, config) ==
                   PM3000_ACME_CONFIG_OK
               ? PM3000_ACME_ADMIN_OK : PM3000_ACME_ADMIN_INVALID;
}

static int valid_etag(const char *etag)
{
    unsigned int index;
    if (etag == (const char *)0 || etag[0] != '\"') return 0;
    for (index = 1U; index <= 64U; ++index)
        if (!((etag[index] >= '0' && etag[index] <= '9') ||
              (etag[index] >= 'a' && etag[index] <= 'f')))
            return 0;
    return etag[65] == '\"' && etag[66] == '\0';
}

static int config_revision_at(int root_fd, const char *managed_path,
                              char *output, unsigned int output_capacity)
{
    static const char hex[] = "0123456789abcdef";
    struct pm3000_acme_runtime_config config;
    struct pm3000_acme_stat details;
    unsigned char digest[PM3000_ACME_SHA256_BYTES];
    unsigned int length = 0U;
    unsigned int ca_length = 0U;
    unsigned int index;
    int trust_fd = -1;
    int result;
    if (managed_path == (const char *)0 || output == (char *)0 ||
        output_capacity < PM3000_ACME_ADMIN_ETAG_BYTES)
        return PM3000_ACME_ADMIN_INVALID;
    result = read_config(root_fd, &config);
    if (result != PM3000_ACME_ADMIN_OK) return result;
    if (pm3000_acme_config_serialize(&config, revision_buffer,
                                     PM3000_ACME_CONFIG_MAX_BYTES,
                                     &length) != PM3000_ACME_CONFIG_OK)
        return PM3000_ACME_ADMIN_IO;
    if (strcmp(config.ca_file, managed_path) == 0) {
        trust_fd = openat(root_fd, "trust",
                          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
        if (trust_fd < 0 || pm3000_acme_fstat(trust_fd, &details) != 0 ||
            !PM3000_ACME_S_ISDIR(details.mode) ||
            details.uid != (unsigned long)geteuid() ||
            (details.mode & 0777) != 0700 ||
            pm3000_acme_store_read_at(
                trust_fd, "managed-ca.pem", revision_buffer + length,
                PM3000_ACME_CA_BUNDLE_MAX + 1U, &ca_length, 1) !=
                PM3000_ACME_STORE_OK) {
            if (trust_fd >= 0) close(trust_fd);
            return PM3000_ACME_ADMIN_UNSAFE;
        }
        close(trust_fd);
        length += ca_length;
    }
    if (pm3000_acme_crypto_sha256(revision_buffer, length, digest) !=
            PM3000_ACME_CRYPTO_OK)
        return PM3000_ACME_ADMIN_IO;
    output[0] = '\"';
    for (index = 0U; index < sizeof(digest); ++index) {
        output[1U + index * 2U] = hex[digest[index] >> 4];
        output[2U + index * 2U] = hex[digest[index] & 15U];
    }
    output[65] = '\"';
    output[66] = '\0';
    return PM3000_ACME_ADMIN_OK;
}

int pm3000_acme_admin_config_revision(
    const char *root, const char *managed_path,
    char *output, unsigned int output_capacity)
{
    struct pm3000_acme_state state;
    int result;
    if (pm3000_acme_state_open_root(root, &state) != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    result = config_revision_at(state.root_fd, managed_path, output,
                                output_capacity);
    pm3000_acme_state_close(&state);
    return result;
}

static int revision_matches(int root_fd, const char *managed_path,
                            const char *expected_revision)
{
    char current[PM3000_ACME_ADMIN_ETAG_BYTES];
    int result;
    if (expected_revision == (const char *)0) return PM3000_ACME_ADMIN_OK;
    if (!valid_etag(expected_revision)) return PM3000_ACME_ADMIN_INVALID;
    result = config_revision_at(root_fd, managed_path, current, sizeof(current));
    if (result != PM3000_ACME_ADMIN_OK) return result;
    return strcmp(current, expected_revision) == 0
               ? PM3000_ACME_ADMIN_OK : PM3000_ACME_ADMIN_STALE;
}

int pm3000_acme_admin_config_show(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    struct pm3000_acme_state state;
    struct pm3000_acme_runtime_config config;
    int result;
    if (output == (unsigned char *)0 || output_length == (unsigned int *)0)
        return PM3000_ACME_ADMIN_INVALID;
    *output_length = 0U;
    if (pm3000_acme_state_open_root(root, &state) != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    result = read_config(state.root_fd, &config);
    if (result == PM3000_ACME_ADMIN_OK &&
        pm3000_acme_config_serialize(&config, output, output_capacity,
                                     output_length) !=
            PM3000_ACME_CONFIG_OK)
        result = PM3000_ACME_ADMIN_IO;
    pm3000_acme_state_close(&state);
    return result;
}

static int config_replace(
    const char *root, const char *managed_path, const char *expected_revision,
    const unsigned char *input, unsigned int input_length)
{
    struct pm3000_acme_state state;
    struct pm3000_acme_runtime_config config;
    unsigned int canonical_length = 0U;
    unsigned int verify_length = 0U;
    int state_result;
    int store_result;
    int result = PM3000_ACME_ADMIN_IO;
    if (input == (const unsigned char *)0 || input_length == 0U ||
        input_length > PM3000_ACME_CONFIG_MAX_BYTES ||
        pm3000_acme_config_parse(input, input_length, &config) !=
            PM3000_ACME_CONFIG_OK ||
        pm3000_acme_config_serialize(&config, config_buffer,
                                     sizeof(config_buffer),
                                     &canonical_length) !=
            PM3000_ACME_CONFIG_OK)
        return PM3000_ACME_ADMIN_INVALID;
    state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    result = revision_matches(state.root_fd, managed_path, expected_revision);
    if (result != PM3000_ACME_ADMIN_OK) goto done;
    store_result = pm3000_acme_store_write_at(
        state.root_fd, "config.json", config_buffer, canonical_length, 0600);
    if (store_result != PM3000_ACME_STORE_OK &&
        store_result != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        goto done;
    if (pm3000_acme_store_read_at(state.root_fd, "config.json", verify_buffer,
                                  PM3000_ACME_CONFIG_MAX_BYTES,
                                  &verify_length, 1) != PM3000_ACME_STORE_OK ||
        verify_length != canonical_length ||
        memcmp(verify_buffer, config_buffer, canonical_length) != 0)
        goto done;
    result = store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN
                 ? PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN
                 : PM3000_ACME_ADMIN_OK;
done:
    pm3000_acme_state_close(&state);
    return result;
}

int pm3000_acme_admin_config_replace(
    const char *root, const unsigned char *input, unsigned int input_length)
{
    return config_replace(root, (const char *)0, (const char *)0,
                          input, input_length);
}

int pm3000_acme_admin_config_replace_if_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length,
    const char *expected_revision)
{
    if (managed_path == (const char *)0 || expected_revision == (const char *)0)
        return PM3000_ACME_ADMIN_INVALID;
    return config_replace(root, managed_path, expected_revision,
                          input, input_length);
}

int pm3000_acme_admin_config_create_if_none_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length)
{
    struct pm3000_acme_state state;
    struct pm3000_acme_runtime_config config;
    struct pm3000_acme_stat details;
    unsigned int canonical_length = 0U;
    unsigned int ca_length = 0U;
    unsigned int verify_length = 0U;
    int trust_fd = -1;
    int state_result;
    int store_result;
    int result = PM3000_ACME_ADMIN_IO;
    if (root == (const char *)0 || managed_path == (const char *)0 ||
        input == (const unsigned char *)0 || input_length == 0U ||
        input_length > PM3000_ACME_CONFIG_MAX_BYTES ||
        pm3000_acme_config_parse(input, input_length, &config) !=
            PM3000_ACME_CONFIG_OK ||
        strcmp(config.ca_file, managed_path) != 0 ||
        pm3000_acme_config_serialize(&config, config_buffer,
                                     sizeof(config_buffer),
                                     &canonical_length) !=
            PM3000_ACME_CONFIG_OK)
        return PM3000_ACME_ADMIN_INVALID;
    state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    state_result = entry_absent_at(state.root_fd, "config.json");
    if (state_result == 0) {
        result = PM3000_ACME_ADMIN_STALE;
        goto done;
    }
    if (state_result != 1) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    trust_fd = openat(state.root_fd, "trust",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (trust_fd < 0 || pm3000_acme_fstat(trust_fd, &details) != 0 ||
        !PM3000_ACME_S_ISDIR(details.mode) ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0700 ||
        pm3000_acme_store_read_at(trust_fd, "managed-ca.pem", ca_verify_buffer,
                                  sizeof(ca_verify_buffer), &ca_length, 1) !=
            PM3000_ACME_STORE_OK ||
        pm3000_acme_certificate_validate_ca_bundle(ca_verify_buffer, ca_length) !=
            PM3000_ACME_CERTIFICATE_OK) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    store_result = pm3000_acme_store_write_at(
        state.root_fd, "config.json", config_buffer, canonical_length, 0600);
    if (store_result != PM3000_ACME_STORE_OK &&
        store_result != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        goto done;
    if (pm3000_acme_store_read_at(state.root_fd, "config.json", verify_buffer,
                                  PM3000_ACME_CONFIG_MAX_BYTES,
                                  &verify_length, 1) != PM3000_ACME_STORE_OK ||
        verify_length != canonical_length ||
        memcmp(verify_buffer, config_buffer, canonical_length) != 0)
        goto done;
    result = store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN
                 ? PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN
                 : PM3000_ACME_ADMIN_OK;
done:
    if (trust_fd >= 0) close(trust_fd);
    pm3000_acme_state_close(&state);
    return result;
}

static int ca_install(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length,
    const char *expected_revision)
{
    struct pm3000_acme_state state;
    struct pm3000_acme_runtime_config config;
    struct pm3000_acme_stat details;
    unsigned int canonical_length = 0U;
    unsigned int verify_length = 0U;
    unsigned int path_length;
    int trust_fd = -1;
    int state_result;
    int store_result;
    int result = PM3000_ACME_ADMIN_IO;
    if (root == (const char *)0 || managed_path == (const char *)0 ||
        input == (const unsigned char *)0 || input_length == 0U ||
        input_length > PM3000_ACME_CA_BUNDLE_MAX ||
        pm3000_acme_certificate_validate_ca_bundle(input, input_length) !=
            PM3000_ACME_CERTIFICATE_OK)
        return PM3000_ACME_ADMIN_INVALID;
    path_length = (unsigned int)strlen(managed_path);
    if (path_length == 0U || path_length > PM3000_ACME_CA_PATH_MAX ||
        managed_path[0] != '/' ||
        path_length < strlen("/trust/managed-ca.pem") ||
        strcmp(managed_path + path_length - strlen("/trust/managed-ca.pem"),
               "/trust/managed-ca.pem") != 0)
        return PM3000_ACME_ADMIN_INVALID;
    state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    if (read_config(state.root_fd, &config) != PM3000_ACME_ADMIN_OK)
        goto done;
    trust_fd = openat(state.root_fd, "trust",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (trust_fd < 0 || pm3000_acme_fstat(trust_fd, &details) != 0 ||
        !PM3000_ACME_S_ISDIR(details.mode) ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0700) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    result = revision_matches(state.root_fd, managed_path, expected_revision);
    if (result != PM3000_ACME_ADMIN_OK) goto done;
    store_result = pm3000_acme_store_write_at(
        trust_fd, "managed-ca.pem", input, input_length, 0600);
    if (store_result != PM3000_ACME_STORE_OK &&
        store_result != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        goto done;
    memcpy(config.ca_file, managed_path, path_length + 1U);
    if (pm3000_acme_config_serialize(&config, config_buffer,
                                     sizeof(config_buffer),
                                     &canonical_length) !=
            PM3000_ACME_CONFIG_OK)
        goto done;
    {
        int config_store = pm3000_acme_store_write_at(
            state.root_fd, "config.json", config_buffer, canonical_length, 0600);
        if (config_store != PM3000_ACME_STORE_OK &&
            config_store != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
            goto done;
        if (config_store == PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
            store_result = PM3000_ACME_STORE_COMMITTED_UNCERTAIN;
    }
    if (pm3000_acme_store_read_at(trust_fd, "managed-ca.pem", ca_verify_buffer,
                                  sizeof(ca_verify_buffer), &verify_length, 1) !=
            PM3000_ACME_STORE_OK || verify_length != input_length ||
        memcmp(ca_verify_buffer, input, input_length) != 0)
        goto done;
    result = store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN
                 ? PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN
                 : PM3000_ACME_ADMIN_OK;
done:
    if (trust_fd >= 0) close(trust_fd);
    pm3000_acme_state_close(&state);
    return result;
}

int pm3000_acme_admin_ca_install(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length)
{
    return ca_install(root, managed_path, input, input_length,
                      (const char *)0);
}

int pm3000_acme_admin_ca_install_if_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length,
    const char *expected_revision)
{
    if (expected_revision == (const char *)0)
        return PM3000_ACME_ADMIN_INVALID;
    return ca_install(root, managed_path, input, input_length,
                      expected_revision);
}

int pm3000_acme_admin_ca_create_if_none_match(
    const char *root, const char *managed_path,
    const unsigned char *input, unsigned int input_length)
{
    struct pm3000_acme_state state;
    struct pm3000_acme_stat details;
    unsigned int verify_length = 0U;
    unsigned int path_length;
    int trust_fd = -1;
    int state_result;
    int store_result;
    int result = PM3000_ACME_ADMIN_IO;
    if (root == (const char *)0 || managed_path == (const char *)0 ||
        input == (const unsigned char *)0 || input_length == 0U ||
        input_length > PM3000_ACME_CA_BUNDLE_MAX ||
        pm3000_acme_certificate_validate_ca_bundle(input, input_length) !=
            PM3000_ACME_CERTIFICATE_OK)
        return PM3000_ACME_ADMIN_INVALID;
    path_length = (unsigned int)strlen(managed_path);
    if (path_length == 0U || path_length > PM3000_ACME_CA_PATH_MAX ||
        managed_path[0] != '/' ||
        path_length < strlen("/trust/managed-ca.pem") ||
        strcmp(managed_path + path_length - strlen("/trust/managed-ca.pem"),
               "/trust/managed-ca.pem") != 0)
        return PM3000_ACME_ADMIN_INVALID;
    state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    state_result = entry_absent_at(state.root_fd, "config.json");
    if (state_result == 0) {
        result = PM3000_ACME_ADMIN_STALE;
        goto done;
    }
    if (state_result != 1) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    trust_fd = openat(state.root_fd, "trust",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (trust_fd < 0 || pm3000_acme_fstat(trust_fd, &details) != 0 ||
        !PM3000_ACME_S_ISDIR(details.mode) ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0700) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    state_result = entry_absent_at(trust_fd, "managed-ca.pem");
    if (state_result == 0) {
        result = PM3000_ACME_ADMIN_STALE;
        goto done;
    }
    if (state_result != 1) {
        result = PM3000_ACME_ADMIN_UNSAFE;
        goto done;
    }
    store_result = pm3000_acme_store_write_at(
        trust_fd, "managed-ca.pem", input, input_length, 0600);
    if (store_result != PM3000_ACME_STORE_OK &&
        store_result != PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        goto done;
    if (pm3000_acme_store_read_at(trust_fd, "managed-ca.pem", ca_verify_buffer,
                                  sizeof(ca_verify_buffer), &verify_length, 1) !=
            PM3000_ACME_STORE_OK || verify_length != input_length ||
        memcmp(ca_verify_buffer, input, input_length) != 0)
        goto done;
    result = store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN
                 ? PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN
                 : PM3000_ACME_ADMIN_OK;
done:
    if (trust_fd >= 0) close(trust_fd);
    pm3000_acme_state_close(&state);
    return result;
}

int pm3000_acme_admin_bootstrap_status(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    static const unsigned char absent[] = "{\"ca_installed\":false}\n";
    static const unsigned char installed[] = "{\"ca_installed\":true}\n";
    struct pm3000_acme_state state;
    struct pm3000_acme_stat details;
    const unsigned char *selected = absent;
    unsigned int selected_length = sizeof(absent) - 1U;
    unsigned int ca_length = 0U;
    int trust_fd = -1;
    int probe;
    int result = PM3000_ACME_ADMIN_UNSAFE;
    if (output == (unsigned char *)0 || output_length == (unsigned int *)0)
        return PM3000_ACME_ADMIN_INVALID;
    *output_length = 0U;
    if (pm3000_acme_state_open_root(root, &state) != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    probe = entry_absent_at(state.root_fd, "config.json");
    if (probe == 0) {
        result = PM3000_ACME_ADMIN_STALE;
        goto done;
    }
    if (probe != 1) goto done;
    trust_fd = openat(state.root_fd, "trust",
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_NONBLOCK);
    if (trust_fd < 0 || pm3000_acme_fstat(trust_fd, &details) != 0 ||
        !PM3000_ACME_S_ISDIR(details.mode) ||
        details.uid != (unsigned long)geteuid() ||
        (details.mode & 0777) != 0700)
        goto done;
    probe = entry_absent_at(trust_fd, "managed-ca.pem");
    if (probe == 0) {
        if (pm3000_acme_store_read_at(trust_fd, "managed-ca.pem",
                                      ca_verify_buffer,
                                      sizeof(ca_verify_buffer), &ca_length, 1) !=
                PM3000_ACME_STORE_OK ||
            pm3000_acme_certificate_validate_ca_bundle(
                ca_verify_buffer, ca_length) != PM3000_ACME_CERTIFICATE_OK)
            goto done;
        selected = installed;
        selected_length = sizeof(installed) - 1U;
    } else if (probe != 1) {
        goto done;
    }
    if (selected_length > output_capacity) {
        result = PM3000_ACME_ADMIN_IO;
        goto done;
    }
    memcpy(output, selected, selected_length);
    *output_length = selected_length;
    result = PM3000_ACME_ADMIN_OK;
done:
    if (trust_fd >= 0) close(trust_fd);
    pm3000_acme_state_close(&state);
    return result;
}

static int recognized_state_name(const char *state)
{
    static const char *const states[] = {
        "starting", "running", "succeeded", "failed",
        "durability_uncertain"
    };
    unsigned int index;
    if (state == (const char *)0) return 0;
    for (index = 0U; index < sizeof(states) / sizeof(states[0]); ++index)
        if (strcmp(state, states[index]) == 0) return 1;
    return 0;
}

static int recognized_failure_part(const char *value, int phase)
{
    static const char *const phases[] = {
        "directory", "nonce", "account", "order", "authorization",
        "challenge_publication", "challenge_acceptance", "challenge_poll",
        "finalize", "certificate_download", "certificate_validation",
        "certificate_publication"
    };
    static const char *const reasons[] = {
        "tls", "http", "parse", "io", "rejected", "timeout",
        "validation", "publication"
    };
    const char *const *values = phase ? phases : reasons;
    unsigned int count = phase ? sizeof(phases) / sizeof(phases[0]) :
                                 sizeof(reasons) / sizeof(reasons[0]);
    unsigned int index;
    if (value == (const char *)0) return 0;
    for (index = 0U; index < count; ++index)
        if (strcmp(value, values[index]) == 0) return 1;
    return 0;
}

int pm3000_acme_admin_status_write_at(int root_fd, const char *state)
{
    char json[64U];
    int length;
    int store_result;
    if (root_fd < 0 || !recognized_state_name(state))
        return PM3000_ACME_ADMIN_INVALID;
    length = snprintf(json, sizeof(json), "{\"state\":\"%s\"}\n", state);
    if (length <= 0 || (unsigned int)length >= sizeof(json))
        return PM3000_ACME_ADMIN_INVALID;
    store_result = pm3000_acme_store_write_at(
        root_fd, "status.json", (const unsigned char *)json,
        (unsigned int)length, 0600);
    if (store_result == PM3000_ACME_STORE_OK) return PM3000_ACME_ADMIN_OK;
    if (store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        return PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN;
    return PM3000_ACME_ADMIN_IO;
}

int pm3000_acme_admin_status_write(const char *root, const char *status)
{
    struct pm3000_acme_state state;
    int result;
    int state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    result = pm3000_acme_admin_status_write_at(state.root_fd, status);
    pm3000_acme_state_close(&state);
    return result;
}

int pm3000_acme_admin_status_write_failure_at(
    int root_fd, const char *phase, const char *reason)
{
    char json[160U];
    int length;
    int store_result;
    if (root_fd < 0 || !recognized_failure_part(phase, 1) ||
        !recognized_failure_part(reason, 0))
        return PM3000_ACME_ADMIN_INVALID;
    length = snprintf(json, sizeof(json),
                      "{\"state\":\"failed\",\"phase\":\"%s\",\"reason\":\"%s\"}\n",
                      phase, reason);
    if (length <= 0 || (unsigned int)length >= sizeof(json))
        return PM3000_ACME_ADMIN_INVALID;
    store_result = pm3000_acme_store_write_at(
        root_fd, "status.json", (const unsigned char *)json,
        (unsigned int)length, 0600);
    if (store_result == PM3000_ACME_STORE_OK) return PM3000_ACME_ADMIN_OK;
    if (store_result == PM3000_ACME_STORE_COMMITTED_UNCERTAIN)
        return PM3000_ACME_ADMIN_COMMITTED_UNCERTAIN;
    return PM3000_ACME_ADMIN_IO;
}

int pm3000_acme_admin_status_write_failure(
    const char *root, const char *phase, const char *reason)
{
    struct pm3000_acme_state state;
    int result;
    int state_result = pm3000_acme_state_open(root, &state);
    if (state_result == PM3000_ACME_STATE_BUSY)
        return PM3000_ACME_ADMIN_BUSY;
    if (state_result != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    result = pm3000_acme_admin_status_write_failure_at(
        state.root_fd, phase, reason);
    pm3000_acme_state_close(&state);
    return result;
}

static int recognized_status(const unsigned char *data, unsigned int length)
{
    static const char *const states[] = {
        "starting", "running", "succeeded", "failed",
        "durability_uncertain"
    };
    static const char *const phases[] = {
        "directory", "nonce", "account", "order", "authorization",
        "challenge_publication", "challenge_acceptance", "challenge_poll",
        "finalize", "certificate_download", "certificate_validation",
        "certificate_publication"
    };
    static const char *const reasons[] = {
        "tls", "http", "parse", "io", "rejected", "timeout",
        "validation", "publication"
    };
    unsigned int index;
    unsigned int reason_index;
    for (index = 0U; index < sizeof(states) / sizeof(states[0]); ++index) {
        char expected[64];
        int amount = snprintf(expected, sizeof(expected),
                              "{\"state\":\"%s\"}\n", states[index]);
        if (amount > 0 && length == (unsigned int)amount &&
            memcmp(data, expected, length) == 0) return 1;
    }
    for (index = 0U; index < sizeof(phases) / sizeof(phases[0]); ++index)
        for (reason_index = 0U;
             reason_index < sizeof(reasons) / sizeof(reasons[0]);
             ++reason_index) {
            char expected[160U];
            int amount = snprintf(
                expected, sizeof(expected),
                "{\"state\":\"failed\",\"phase\":\"%s\",\"reason\":\"%s\"}\n",
                phases[index], reasons[reason_index]);
            if (amount > 0 && length == (unsigned int)amount &&
                memcmp(data, expected, length) == 0) return 1;
        }
    return 0;
}

static int status_is_active(const unsigned char *data, unsigned int length)
{
    static const unsigned char starting[] = "{\"state\":\"starting\"}\n";
    static const unsigned char running[] = "{\"state\":\"running\"}\n";
    return (length == sizeof(starting) - 1U &&
            memcmp(data, starting, sizeof(starting) - 1U) == 0) ||
           (length == sizeof(running) - 1U &&
            memcmp(data, running, sizeof(running) - 1U) == 0);
}

int pm3000_acme_admin_status(
    const char *root, unsigned char *output, unsigned int output_capacity,
    unsigned int *output_length)
{
    static const unsigned char never_run[] = "{\"state\":\"never_run\"}\n";
    static const unsigned char unknown[] = "{\"state\":\"unknown\"}\n";
    struct pm3000_acme_state state;
    unsigned char stored[160U];
    unsigned int length = 0U;
    const unsigned char *selected = stored;
    unsigned int selected_length = 0U;
    int read_result;
    int probe;
    if (output == (unsigned char *)0 || output_length == (unsigned int *)0)
        return PM3000_ACME_ADMIN_INVALID;
    *output_length = 0U;
    if (pm3000_acme_state_open_root(root, &state) != PM3000_ACME_STATE_OK)
        return PM3000_ACME_ADMIN_UNSAFE;
    read_result = pm3000_acme_store_read_at(state.root_fd, "status.json",
                                            stored, sizeof(stored), &length, 1);
    if (read_result == PM3000_ACME_STORE_OK && recognized_status(stored, length)) {
        selected_length = length;
        if (status_is_active(stored, length)) {
            struct pm3000_acme_state locked;
            int lock_result = pm3000_acme_state_open(root, &locked);
            if (lock_result == PM3000_ACME_STATE_OK) {
                pm3000_acme_state_close(&locked);
                selected = unknown;
                selected_length = sizeof(unknown) - 1U;
            } else if (lock_result != PM3000_ACME_STATE_BUSY) {
                pm3000_acme_state_close(&state);
                return PM3000_ACME_ADMIN_IO;
            }
        }
    } else {
        probe = openat(state.root_fd, "status.json", O_RDONLY | O_NOFOLLOW);
        if (probe < 0 && errno == ENOENT) {
            selected = never_run;
            selected_length = sizeof(never_run) - 1U;
        } else {
            if (probe >= 0) close(probe);
            selected = unknown;
            selected_length = sizeof(unknown) - 1U;
        }
    }
    if (selected_length > output_capacity) {
        pm3000_acme_state_close(&state);
        return PM3000_ACME_ADMIN_IO;
    }
    memcpy(output, selected, selected_length);
    *output_length = selected_length;
    pm3000_acme_state_close(&state);
    return PM3000_ACME_ADMIN_OK;
}
