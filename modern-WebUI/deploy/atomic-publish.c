#define _POSIX_C_SOURCE 200809L

#include <dirent.h>
#include <errno.h>
#include <fcntl.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int safe_name(const char *value) {
    return value[0] != '\0' && strcmp(value, ".") != 0 && strcmp(value, "..") != 0 &&
           strchr(value, '/') == NULL;
}

static int verify_entries(int directory_fd, const char *const *names, size_t count) {
    DIR *directory;
    struct dirent *entry;
    unsigned int seen = 0;
    size_t index;
    int duplicate = dup(directory_fd);
    if (duplicate < 0 || (directory = fdopendir(duplicate)) == NULL) {
        if (duplicate >= 0) close(duplicate);
        return -1;
    }
    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) continue;
        for (index = 0; index < count; index++) {
            if (strcmp(entry->d_name, names[index]) == 0) break;
        }
        if (index == count || (seen & (1U << index)) != 0U) {
            closedir(directory);
            return -1;
        }
        seen |= 1U << index;
    }
    if (errno != 0 || closedir(directory) != 0) return -1;
    return seen == ((1U << count) - 1U) ? 0 : -1;
}

static int verify_regular_at(int directory_fd, const char *name, mode_t mode) {
    int file_fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat value;
    if (file_fd < 0) return -1;
    if (fstat(file_fd, &value) != 0 || !S_ISREG(value.st_mode)
            || value.st_nlink != 1 || value.st_uid != geteuid()
            || (value.st_mode & 07777) != mode) {
        close(file_fd);
        return -1;
    }
    return close(file_fd);
}

static int verify_group_at(int directory_fd, const char *name, gid_t group) {
    int file_fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
    struct stat value;
    int result = -1;
    if (file_fd < 0) return -1;
    if (fstat(file_fd, &value) == 0 && S_ISREG(value.st_mode) && value.st_gid == group)
        result = 0;
    if (close(file_fd) != 0) result = -1;
    return result;
}

static int verify_subdirectory(int root_fd, const char *name,
                               const char *const *files, const mode_t *modes, size_t count) {
    int directory_fd = openat(root_fd, name, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat value;
    size_t index;
    if (directory_fd < 0) return -1;
    if (fstat(directory_fd, &value) != 0 || !S_ISDIR(value.st_mode)
            || value.st_uid != geteuid() || (value.st_mode & 07777) != 0755
            || verify_entries(directory_fd, files, count) != 0) {
        close(directory_fd);
        return -1;
    }
    for (index = 0; index < count; index++) {
        if (verify_regular_at(directory_fd, files[index], modes[index]) != 0) {
            close(directory_fd);
            return -1;
        }
    }
    return close(directory_fd);
}

static int verify_release(const char *path, gid_t expected_helper_group, int verify_helper_group) {
    static const char *const root_names[] = {
        "RELEASE_MANIFEST.json", "RELEASE_SHA256SUMS", "apache", "bin", "web"
    };
    static const char *const apache_files[] = {"pm3000-revive.conf"};
    static const mode_t apache_modes[] = {0644};
    static const char *const bin_files[] = {
        "pm3000-atomic-publish", "pm3000-gsp-session-helper", "pm3000-rest"
    };
    static const mode_t bin_modes[] = {0755, 04750, 0755};
    static const char *const web_files[] = {"app.js", "index.html", "styles.css"};
    static const mode_t web_modes[] = {0644, 0644, 0644};
    int root_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    int bin_fd = -1;
    struct stat root;
    int result = -1;
    if (root_fd < 0) return -1;
    if (fstat(root_fd, &root) == 0 && S_ISDIR(root.st_mode)
            && root.st_uid == geteuid() && (root.st_mode & 07777) == 0755
            && verify_entries(root_fd, root_names, 5) == 0
            && verify_regular_at(root_fd, "RELEASE_MANIFEST.json", 0600) == 0
            && verify_regular_at(root_fd, "RELEASE_SHA256SUMS", 0600) == 0
            && verify_subdirectory(root_fd, "apache", apache_files, apache_modes, 1) == 0
            && verify_subdirectory(root_fd, "bin", bin_files, bin_modes, 3) == 0
            && verify_subdirectory(root_fd, "web", web_files, web_modes, 3) == 0) {
        bin_fd = openat(root_fd, "bin", O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (bin_fd >= 0 && (!verify_helper_group ||
                verify_group_at(bin_fd, "pm3000-gsp-session-helper",
                                expected_helper_group) == 0))
            result = 0;
    }
    if (bin_fd >= 0 && close(bin_fd) != 0) result = -1;
    if (close(root_fd) != 0) result = -1;
    return result;
}

static int parse_id(const char *value, unsigned long maximum, unsigned long *parsed) {
    char *end = NULL;
    errno = 0;
    *parsed = strtoul(value, &end, 10);
    return errno == 0 && value[0] != '\0' && end != NULL && *end == '\0' &&
           *parsed <= maximum;
}

int main(int argc, char **argv) {
    int directory_fd;
    struct stat source;
    int expected_type;

    if (argc == 4 &&
            (strcmp(argv[1], "--verify-private-directory-owner") == 0 ||
             strcmp(argv[1], "--verify-private-regular-owner") == 0)) {
        unsigned long parsed = 0UL;
        uid_t expected_owner;
        int descriptor;
        if (!parse_id(argv[3], (unsigned long)(uid_t)-1, &parsed)) {
            fprintf(stderr, "invalid expected owner\n");
            return 2;
        }
        expected_owner = (uid_t)parsed;
        if (strcmp(argv[1], "--verify-private-directory-owner") == 0)
            descriptor = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        else
            descriptor = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (descriptor < 0) {
            perror("open private path");
            return 1;
        }
        if (fstat(descriptor, &source) != 0 || source.st_uid != expected_owner ||
                (strcmp(argv[1], "--verify-private-directory-owner") == 0
                    ? (!S_ISDIR(source.st_mode) || (source.st_mode & 07777) != 0700)
                    : (!S_ISREG(source.st_mode) || source.st_nlink != 1 ||
                       (source.st_mode & 07777) != 0600))) {
            fprintf(stderr, "path is not trusted private storage for expected owner\n");
            close(descriptor);
            return 1;
        }
        return close(descriptor) == 0 ? 0 : 1;
    }

    if (argc == 5 &&
            (strcmp(argv[1], "--set-private-directory-owner") == 0 ||
             strcmp(argv[1], "--set-private-regular-owner") == 0)) {
        unsigned long parsed_uid = 0UL, parsed_gid = 0UL;
        uid_t target_uid;
        gid_t target_gid;
        mode_t target_mode;
        int descriptor;
        int is_directory = strcmp(argv[1], "--set-private-directory-owner") == 0;
        if (!parse_id(argv[3], (unsigned long)(uid_t)-1, &parsed_uid) ||
                !parse_id(argv[4], (unsigned long)(gid_t)-1, &parsed_gid)) {
            fprintf(stderr, "invalid target owner\n");
            return 2;
        }
        target_uid = (uid_t)parsed_uid;
        target_gid = (gid_t)parsed_gid;
        target_mode = is_directory ? 0700 : 0600;
        descriptor = open(argv[2], O_RDONLY | O_NOFOLLOW |
                          (is_directory ? O_DIRECTORY : O_NONBLOCK));
        if (descriptor < 0) {
            perror("open private path for ownership update");
            return 1;
        }
        if (fstat(descriptor, &source) != 0 ||
                (is_directory ? !S_ISDIR(source.st_mode) :
                 (!S_ISREG(source.st_mode) || source.st_nlink != 1)) ||
                (source.st_uid != geteuid() && source.st_uid != target_uid) ||
                fchown(descriptor, target_uid, target_gid) != 0 ||
                fchmod(descriptor, target_mode) != 0 ||
                fstat(descriptor, &source) != 0 || source.st_uid != target_uid ||
                source.st_gid != target_gid ||
                (source.st_mode & 07777) != target_mode) {
            fprintf(stderr, "could not safely set private path ownership\n");
            close(descriptor);
            return 1;
        }
        return close(descriptor) == 0 ? 0 : 1;
    }

    if (argc == 3 && strcmp(argv[1], "--verify-private-directory") == 0) {
        int private_fd = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        if (private_fd < 0) {
            perror("open private directory");
            return 1;
        }
        if (fstat(private_fd, &source) != 0 || !S_ISDIR(source.st_mode)
                || source.st_uid != geteuid() || (source.st_mode & 07777) != 0700) {
            fprintf(stderr, "directory is not trusted private storage\n");
            close(private_fd);
            return 1;
        }
        if (close(private_fd) != 0) {
            perror("close private directory");
            return 1;
        }
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--verify-private-regular") == 0) {
        int file_fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (file_fd < 0) {
            perror("open private regular file");
            return 1;
        }
        if (fstat(file_fd, &source) != 0 || !S_ISREG(source.st_mode)
                || source.st_nlink != 1 || source.st_uid != geteuid()
                || (source.st_mode & 07777) != 0600) {
            fprintf(stderr, "file is not trusted owner-only storage\n");
            close(file_fd);
            return 1;
        }
        if (close(file_fd) != 0) {
            perror("close private regular file");
            return 1;
        }
        return 0;
    }

    if (argc == 3 && strcmp(argv[1], "--verify-regular") == 0) {
        int file_fd = open(argv[2], O_RDONLY | O_NOFOLLOW | O_NONBLOCK);
        if (file_fd < 0) {
            perror("open regular file");
            return 1;
        }
        if (fstat(file_fd, &source) != 0 || !S_ISREG(source.st_mode)
                || source.st_nlink != 1 || source.st_uid != geteuid()) {
            fprintf(stderr, "file is not a trusted single-link regular file\n");
            close(file_fd);
            return 1;
        }
        if (close(file_fd) != 0) {
            perror("close regular file");
            return 1;
        }
        return 0;
    }

    if ((argc == 3 || argc == 4) && strcmp(argv[1], "--verify-release") == 0) {
        unsigned long parsed_group = 0UL;
        if (argc == 4 && !parse_id(argv[3], (unsigned long)(gid_t)-1, &parsed_group)) {
            fprintf(stderr, "invalid expected helper group\n");
            return 2;
        }
        if (verify_release(argv[2], (gid_t)parsed_group, argc == 4) != 0) {
            fprintf(stderr, "release tree verification failed\n");
            return 1;
        }
        return 0;
    }

    if (argc != 5 || !safe_name(argv[2]) || !safe_name(argv[3])) {
        fprintf(stderr, "usage: pm3000-atomic-publish --verify-private-directory DIRECTORY | --set-private-regular-owner FILE UID GID | --verify-regular FILE | --verify-release DIRECTORY [HELPER_GID] | DIRECTORY NEW_NAME DEST_NAME symlink|regular|directory\n");
        return 2;
    }
    if (strcmp(argv[4], "symlink") == 0) {
        expected_type = 1;
    } else if (strcmp(argv[4], "regular") == 0) {
        expected_type = 2;
    } else if (strcmp(argv[4], "directory") == 0) {
        expected_type = 3;
    } else {
        fprintf(stderr, "unknown source type\n");
        return 2;
    }
    directory_fd = open(argv[1], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    if (directory_fd < 0) {
        perror("open parent");
        return 1;
    }
    if (fstatat(directory_fd, argv[2], &source, AT_SYMLINK_NOFOLLOW) != 0) {
        perror("inspect source");
        close(directory_fd);
        return 1;
    }
    if ((expected_type == 1 && !S_ISLNK(source.st_mode)) ||
        (expected_type == 2 && !S_ISREG(source.st_mode)) ||
        (expected_type == 3 && !S_ISDIR(source.st_mode))) {
        fprintf(stderr, "source has unexpected type\n");
        close(directory_fd);
        return 1;
    }
    if (renameat(directory_fd, argv[2], directory_fd, argv[3]) != 0) {
        perror("renameat");
        close(directory_fd);
        return 1;
    }
    if (fsync(directory_fd) != 0) {
        perror("fsync parent");
        close(directory_fd);
        return 1;
    }
    if (close(directory_fd) != 0) {
        perror("close parent");
        return 1;
    }
    return 0;
}
