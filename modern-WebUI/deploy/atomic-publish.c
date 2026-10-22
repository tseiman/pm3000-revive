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
    int file_fd = openat(directory_fd, name, O_RDONLY | O_NOFOLLOW);
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

static int verify_release(const char *path) {
    static const char *const root_names[] = {
        "RELEASE_MANIFEST.json", "RELEASE_SHA256SUMS", "apache", "bin", "web"
    };
    static const char *const apache_files[] = {"pm3000-revive.conf"};
    static const mode_t apache_modes[] = {0644};
    static const char *const bin_files[] = {"pm3000-atomic-publish", "pm3000-rest"};
    static const mode_t bin_modes[] = {0755, 0755};
    static const char *const web_files[] = {"app.js", "index.html", "styles.css"};
    static const mode_t web_modes[] = {0644, 0644, 0644};
    int root_fd = open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
    struct stat root;
    int result = -1;
    if (root_fd < 0) return -1;
    if (fstat(root_fd, &root) == 0 && S_ISDIR(root.st_mode)
            && root.st_uid == geteuid() && (root.st_mode & 07777) == 0755
            && verify_entries(root_fd, root_names, 5) == 0
            && verify_regular_at(root_fd, "RELEASE_MANIFEST.json", 0600) == 0
            && verify_regular_at(root_fd, "RELEASE_SHA256SUMS", 0600) == 0
            && verify_subdirectory(root_fd, "apache", apache_files, apache_modes, 1) == 0
            && verify_subdirectory(root_fd, "bin", bin_files, bin_modes, 2) == 0
            && verify_subdirectory(root_fd, "web", web_files, web_modes, 3) == 0) result = 0;
    if (close(root_fd) != 0) result = -1;
    return result;
}

int main(int argc, char **argv) {
    int directory_fd;
    struct stat source;
    int expected_type;

    if (argc == 4 &&
            (strcmp(argv[1], "--verify-private-directory-owner") == 0 ||
             strcmp(argv[1], "--verify-private-regular-owner") == 0)) {
        char *end = NULL;
        unsigned long parsed;
        uid_t expected_owner;
        int descriptor;
        errno = 0;
        parsed = strtoul(argv[3], &end, 10);
        expected_owner = (uid_t)parsed;
        if (errno != 0 || argv[3][0] == '\0' || end == NULL || *end != '\0' ||
                (unsigned long)expected_owner != parsed) {
            fprintf(stderr, "invalid expected owner\n");
            return 2;
        }
        if (strcmp(argv[1], "--verify-private-directory-owner") == 0)
            descriptor = open(argv[2], O_RDONLY | O_DIRECTORY | O_NOFOLLOW);
        else
            descriptor = open(argv[2], O_RDONLY | O_NOFOLLOW);
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
        int file_fd = open(argv[2], O_RDONLY | O_NOFOLLOW);
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
        int file_fd = open(argv[2], O_RDONLY | O_NOFOLLOW);
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

    if (argc == 3 && strcmp(argv[1], "--verify-release") == 0) {
        if (verify_release(argv[2]) != 0) {
            fprintf(stderr, "release tree verification failed\n");
            return 1;
        }
        return 0;
    }

    if (argc != 5 || !safe_name(argv[2]) || !safe_name(argv[3])) {
        fprintf(stderr, "usage: pm3000-atomic-publish --verify-private-directory DIRECTORY | --verify-regular FILE | --verify-release DIRECTORY | DIRECTORY NEW_NAME DEST_NAME symlink|regular|directory\n");
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
