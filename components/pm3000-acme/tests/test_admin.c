#define _POSIX_C_SOURCE 200809L

#include "pm3000_acme_admin.h"
#include "pm3000_acme_certificate.h"
#include "pm3000_acme_store.h"

#include <errno.h>
#include <stdio.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

static unsigned char boundary_ca[PM3000_ACME_CA_BUNDLE_MAX + 1U];
static unsigned char boundary_readback[PM3000_ACME_CA_BUNDLE_MAX + 1U];

int main(void)
{
    char root[] = "build/admin-test-XXXXXX";
    char bootstrap_root[] = "build/admin-bootstrap-test-XXXXXX";
    static const unsigned char initial[] =
        "{\"enabled\":false,\"directory_url\":\"https://acme.example.test/old\","
        "\"ca_file\":\"/etc/CA/root.pem\",\"dns_names\":[\"PDU1.TSEI.MDN\"]}";
    static const unsigned char canonical[] =
        "{\"enabled\":false,\"directory_url\":\"https://acme.example.test/old\","
        "\"ca_file\":\"/etc/CA/root.pem\",\"dns_names\":[\"pdu1.tsei.mdn\"]}\n";
    static const unsigned char replacement[] =
        "{\"enabled\":true,\"directory_url\":\"https://acme.example.test/new\","
        "\"ca_file\":\"/etc/CA/new.pem\",\"dns_names\":[\"pdu2.tsei.mdn\"]}";
    static const unsigned char replaced[] =
        "{\"enabled\":true,\"directory_url\":\"https://acme.example.test/new\","
        "\"ca_file\":\"/etc/CA/new.pem\",\"dns_names\":[\"pdu2.tsei.mdn\"]}\n";
    static const unsigned char succeeded[] = "{\"state\":\"succeeded\"}\n";
    unsigned char output[PM3000_ACME_ADMIN_OUTPUT_MAX];
    unsigned char stored[PM3000_ACME_CONFIG_MAX_BYTES + 1U];
    unsigned int output_length = 0U;
    unsigned int stored_length = 0U;
    struct stat status_details;
    char status_path[256];
    char trust_path[256];
    char managed_path[1024];
    char bootstrap_trust_path[256];
    char bootstrap_managed_path[1024];
    unsigned char ca_bundle[65536U];
    unsigned int ca_length = 0U;
    char revision[PM3000_ACME_ADMIN_ETAG_BYTES];
    char managed_revision[PM3000_ACME_ADMIN_ETAG_BYTES];
    FILE *ca_file;
    size_t ca_amount;

    ca_file = fopen("tests/fixtures/tls/ca.pem", "rb");
    if (ca_file == NULL) return 2;
    ca_amount = fread(ca_bundle, 1U, sizeof(ca_bundle), ca_file);
    if (ferror(ca_file) || !feof(ca_file) || fclose(ca_file) != 0 ||
        ca_amount == 0U) return 2;
    ca_length = (unsigned int)ca_amount;
    memcpy(boundary_ca, ca_bundle, ca_length);
    memset(boundary_ca + ca_length, ' ', sizeof(boundary_ca) - ca_length);

    if (mkdtemp(bootstrap_root) == NULL || chmod(bootstrap_root, 0700) != 0 ||
        snprintf(bootstrap_trust_path, sizeof(bootstrap_trust_path),
                 "%s/trust", bootstrap_root) < 0 ||
        mkdir(bootstrap_trust_path, 0700) != 0 ||
        getcwd(bootstrap_managed_path, sizeof(bootstrap_managed_path)) == NULL ||
        strlen(bootstrap_managed_path) + strlen(bootstrap_root) +
                strlen("//trust/managed-ca.pem") + 1U >
            sizeof(bootstrap_managed_path) ||
        strcat(bootstrap_managed_path, "/") == NULL ||
        strcat(bootstrap_managed_path, bootstrap_root) == NULL ||
        strcat(bootstrap_managed_path, "/trust/managed-ca.pem") == NULL)
        return 2;
    {
        unsigned char bootstrap_config[2048];
        int bootstrap_length = snprintf(
            (char *)bootstrap_config, sizeof(bootstrap_config),
            "{\"enabled\":false,\"directory_url\":\"https://bootstrap.example.test/directory\","
            "\"ca_file\":\"%s\",\"dns_names\":[\"pdu.bootstrap.example.test\"]}",
            bootstrap_managed_path);
        char bootstrap_ca_path[512];
        char bootstrap_config_path[512];
        if (bootstrap_length <= 0 ||
            (unsigned int)bootstrap_length >= sizeof(bootstrap_config) ||
            snprintf(bootstrap_ca_path, sizeof(bootstrap_ca_path),
                     "%s/trust/managed-ca.pem", bootstrap_root) < 0 ||
            snprintf(bootstrap_config_path, sizeof(bootstrap_config_path),
                     "%s/config.json", bootstrap_root) < 0 ||
            pm3000_acme_admin_config_show(
                bootstrap_root, output, sizeof(output), &output_length) !=
                PM3000_ACME_ADMIN_NOT_FOUND ||
            pm3000_acme_admin_config_revision(
                bootstrap_root, bootstrap_managed_path, revision,
                sizeof(revision)) != PM3000_ACME_ADMIN_NOT_FOUND ||
            pm3000_acme_admin_ca_create_if_none_match(
                bootstrap_root, bootstrap_managed_path, boundary_ca,
                PM3000_ACME_CA_BUNDLE_MAX + 1U) != PM3000_ACME_ADMIN_INVALID ||
            access(bootstrap_ca_path, F_OK) == 0 || errno != ENOENT ||
            pm3000_acme_admin_ca_create_if_none_match(
                bootstrap_root, bootstrap_managed_path, boundary_ca,
                PM3000_ACME_CA_BUNDLE_MAX) !=
                PM3000_ACME_ADMIN_OK ||
            pm3000_acme_store_read(
                bootstrap_trust_path, "managed-ca.pem", boundary_readback,
                sizeof(boundary_readback), &stored_length, 1) !=
                PM3000_ACME_STORE_OK ||
            stored_length != PM3000_ACME_CA_BUNDLE_MAX ||
            memcmp(boundary_readback, boundary_ca,
                   PM3000_ACME_CA_BUNDLE_MAX) != 0 ||
            pm3000_acme_admin_bootstrap_status(
                bootstrap_root, output, sizeof(output), &output_length) !=
                PM3000_ACME_ADMIN_OK ||
            output_length != strlen("{\"ca_installed\":true}\n") ||
            memcmp(output, "{\"ca_installed\":true}\n", output_length) != 0 ||
            pm3000_acme_admin_ca_create_if_none_match(
                bootstrap_root, bootstrap_managed_path, ca_bundle, ca_length) !=
                PM3000_ACME_ADMIN_STALE ||
            pm3000_acme_admin_config_create_if_none_match(
                bootstrap_root, bootstrap_managed_path, bootstrap_config,
                (unsigned int)bootstrap_length) != PM3000_ACME_ADMIN_OK ||
            pm3000_acme_admin_config_create_if_none_match(
                bootstrap_root, bootstrap_managed_path, bootstrap_config,
                (unsigned int)bootstrap_length) != PM3000_ACME_ADMIN_STALE ||
            pm3000_acme_admin_config_revision(
                bootstrap_root, bootstrap_managed_path, revision,
                sizeof(revision)) != PM3000_ACME_ADMIN_OK ||
            stat(bootstrap_ca_path, &status_details) != 0 ||
            (status_details.st_mode & 0777) != 0600 ||
            stat(bootstrap_config_path, &status_details) != 0 ||
            (status_details.st_mode & 0777) != 0600) {
            fprintf(stderr, "first-run conditional bootstrap failed\n");
            return 1;
        }
    }

    if (mkdtemp(root) == NULL || chmod(root, 0700) != 0 ||
        snprintf(trust_path, sizeof(trust_path), "%s/trust", root) < 0 ||
        mkdir(trust_path, 0700) != 0 ||
        getcwd(managed_path, sizeof(managed_path)) == NULL ||
        strlen(managed_path) + strlen(root) +
                strlen("//trust/managed-ca.pem") + 1U > sizeof(managed_path) ||
        strcat(managed_path, "/") == NULL || strcat(managed_path, root) == NULL ||
        strcat(managed_path, "/trust/managed-ca.pem") == NULL ||
        pm3000_acme_store_write(root, "config.json", initial,
                                sizeof(initial) - 1U, 0600) !=
            PM3000_ACME_STORE_OK) return 2;

    if (pm3000_acme_admin_config_show(root, output, sizeof(output),
                                      &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length != sizeof(canonical) - 1U ||
        memcmp(output, canonical, output_length) != 0) {
        fprintf(stderr, "config show failed\n");
        return 1;
    }
    if (pm3000_acme_admin_config_revision(root, managed_path, revision,
                                           sizeof(revision)) !=
            PM3000_ACME_ADMIN_OK ||
        strcmp(revision,
               "\"296f222e33040ccdd5a9617bfbbfc1ebd92d61b1b3ab72855ec183379f078f81\"") != 0) {
        fprintf(stderr, "strong config revision failed\n");
        return 1;
    }
    if (pm3000_acme_admin_status(root, output, sizeof(output),
                                 &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length != strlen("{\"state\":\"never_run\"}\n") ||
        memcmp(output, "{\"state\":\"never_run\"}\n", output_length) != 0) {
        fprintf(stderr, "absent status projection failed\n");
        return 1;
    }
    if (pm3000_acme_store_write(root, "status.json", succeeded,
                                sizeof(succeeded) - 1U, 0600) !=
            PM3000_ACME_STORE_OK ||
        pm3000_acme_admin_status(root, output, sizeof(output),
                                 &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length != sizeof(succeeded) - 1U ||
        memcmp(output, succeeded, output_length) != 0) {
        fprintf(stderr, "stored status projection failed\n");
        return 1;
    }
    if (pm3000_acme_admin_status_write_failure(
            root, "directory", "tls") != PM3000_ACME_ADMIN_OK ||
        pm3000_acme_admin_status(root, output, sizeof(output),
                                 &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length != strlen("{\"state\":\"failed\",\"phase\":\"directory\",\"reason\":\"tls\"}\n") ||
        memcmp(output, "{\"state\":\"failed\",\"phase\":\"directory\",\"reason\":\"tls\"}\n",
               output_length) != 0 ||
        pm3000_acme_admin_status_write_failure(root, "invented", "tls") !=
            PM3000_ACME_ADMIN_INVALID) {
        fprintf(stderr, "closed failure diagnostic projection failed\n");
        return 1;
    }
    {
        int ready[2], release[2], wait_status;
        pid_t child;
        char lock_path[256];
        if (pm3000_acme_admin_status_write(root, "running") !=
                PM3000_ACME_ADMIN_OK ||
            snprintf(lock_path, sizeof(lock_path), "%s/renew.lock", root) < 0 ||
            pipe(ready) != 0 || pipe(release) != 0 || (child = fork()) < 0)
            return 2;
        if (child == 0) {
            struct flock lock;
            char byte;
            int descriptor = open(lock_path, O_RDWR | O_NOFOLLOW);
            close(ready[0]); close(release[1]);
            memset(&lock, 0, sizeof(lock));
            lock.l_type = F_WRLCK;
            lock.l_whence = SEEK_SET;
            if (descriptor < 0 || fcntl(descriptor, F_SETLK, &lock) != 0 ||
                write(ready[1], "R", 1U) != 1 ||
                read(release[0], &byte, 1U) != 1)
                _exit(2);
            _exit(0);
        }
        close(ready[1]); close(release[0]);
        if (read(ready[0], stored, 1U) != 1 ||
            pm3000_acme_admin_status(root, output, sizeof(output),
                                     &output_length) != PM3000_ACME_ADMIN_OK ||
            output_length != strlen("{\"state\":\"running\"}\n") ||
            memcmp(output, "{\"state\":\"running\"}\n", output_length) != 0 ||
            write(release[1], "X", 1U) != 1 ||
            waitpid(child, &wait_status, 0) != child ||
            !WIFEXITED(wait_status) || WEXITSTATUS(wait_status) != 0) {
            fprintf(stderr, "active renewal status projection failed\n");
            return 1;
        }
        close(ready[0]); close(release[1]);
    }
    if (snprintf(status_path, sizeof(status_path), "%s/status.json", root) < 0 ||
        pm3000_acme_admin_status_write(root, "running") !=
            PM3000_ACME_ADMIN_OK ||
        stat(status_path, &status_details) != 0 ||
        (status_details.st_mode & 0777) != 0600 ||
        pm3000_acme_admin_status(root, output, sizeof(output),
                                 &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length != strlen("{\"state\":\"unknown\"}\n") ||
        memcmp(output, "{\"state\":\"unknown\"}\n", output_length) != 0 ||
        pm3000_acme_store_read(root, "status.json", stored, sizeof(stored),
                               &stored_length, 1) != PM3000_ACME_STORE_OK ||
        stored_length != strlen("{\"state\":\"running\"}\n") ||
        memcmp(stored, "{\"state\":\"running\"}\n", stored_length) != 0 ||
        pm3000_acme_admin_status_write(root, "invented") !=
            PM3000_ACME_ADMIN_INVALID) {
        fprintf(stderr, "status write contract failed\n");
        return 1;
    }
    if (pm3000_acme_admin_config_replace(root, replacement,
                                         sizeof(replacement) - 1U) !=
            PM3000_ACME_ADMIN_OK ||
        pm3000_acme_store_read(root, "config.json", stored,
                               sizeof(stored), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != sizeof(replaced) - 1U ||
        memcmp(stored, replaced, stored_length) != 0) {
        fprintf(stderr, "config replacement failed\n");
        return 1;
    }
    if (pm3000_acme_admin_config_replace_if_match(
            root, managed_path, initial, sizeof(initial) - 1U, revision) !=
            PM3000_ACME_ADMIN_STALE ||
        pm3000_acme_store_read(root, "config.json", stored,
                               sizeof(stored), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != sizeof(replaced) - 1U ||
        memcmp(stored, replaced, stored_length) != 0) {
        fprintf(stderr, "stale replacement changed config\n");
        return 1;
    }
    if (pm3000_acme_admin_config_revision(root, managed_path, revision,
                                           sizeof(revision)) !=
            PM3000_ACME_ADMIN_OK ||
        pm3000_acme_admin_config_replace_if_match(
            root, managed_path, initial, sizeof(initial) - 1U, revision) !=
            PM3000_ACME_ADMIN_OK ||
        pm3000_acme_store_read(root, "config.json", stored,
                               sizeof(stored), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != sizeof(canonical) - 1U ||
        memcmp(stored, canonical, stored_length) != 0 ||
        pm3000_acme_admin_config_replace(root, replacement,
                                         sizeof(replacement) - 1U) !=
            PM3000_ACME_ADMIN_OK) {
        fprintf(stderr, "matched replacement failed\n");
        return 1;
    }
    if (pm3000_acme_admin_config_replace(
            root, (const unsigned char *)"{}", 2U) !=
            PM3000_ACME_ADMIN_INVALID ||
        pm3000_acme_store_read(root, "config.json", stored,
                               sizeof(stored), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != sizeof(replaced) - 1U ||
        memcmp(stored, replaced, stored_length) != 0) {
        fprintf(stderr, "invalid replacement changed config\n");
        return 1;
    }
    if (pm3000_acme_admin_ca_install(root, managed_path,
                                     boundary_ca,
                                     PM3000_ACME_CA_BUNDLE_MAX) !=
            PM3000_ACME_ADMIN_OK ||
        pm3000_acme_store_read(trust_path, "managed-ca.pem", boundary_readback,
                               sizeof(boundary_readback), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != PM3000_ACME_CA_BUNDLE_MAX ||
        memcmp(boundary_readback, boundary_ca,
               PM3000_ACME_CA_BUNDLE_MAX) != 0 ||
        pm3000_acme_admin_config_show(root, output, sizeof(output),
                                      &output_length) != PM3000_ACME_ADMIN_OK ||
        output_length >= sizeof(output) ||
        (output[output_length] = '\0',
         strstr((const char *)output, "/trust/managed-ca.pem") == NULL)) {
        fprintf(stderr, "managed CA installation failed\n");
        return 1;
    }
    if (pm3000_acme_admin_config_revision(root, managed_path,
                                           managed_revision,
                                           sizeof(managed_revision)) !=
            PM3000_ACME_ADMIN_OK ||
        pm3000_acme_store_write(trust_path, "managed-ca.pem",
                                (const unsigned char *)"changed", 7U, 0600) !=
            PM3000_ACME_STORE_OK ||
        pm3000_acme_admin_config_revision(root, managed_path, revision,
                                           sizeof(revision)) !=
            PM3000_ACME_ADMIN_OK ||
        strcmp(revision, managed_revision) == 0) {
        fprintf(stderr, "managed CA content did not change revision\n");
        return 1;
    }
    if (pm3000_acme_admin_ca_install_if_match(
            root, managed_path, ca_bundle, ca_length, managed_revision) !=
            PM3000_ACME_ADMIN_STALE ||
        pm3000_acme_store_read(trust_path, "managed-ca.pem", stored,
                               sizeof(stored), &stored_length, 1) !=
            PM3000_ACME_STORE_OK ||
        stored_length != 7U || memcmp(stored, "changed", 7U) != 0) {
        fprintf(stderr, "stale CA installation changed state\n");
        return 1;
    }
    puts("admin.tests.complete=yes");
    return 0;
}
