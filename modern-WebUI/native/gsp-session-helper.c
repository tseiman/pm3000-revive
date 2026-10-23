/* Fixed-purpose PM3000 local GSP-AAA session broker.
 * Installed setuid-root, executable only by the Apache daemon group.
 * No arguments, environment input, shell execution, controller operations, or logging.
 */
#define NULL ((void *)0)
typedef unsigned int size_t;
typedef unsigned int socklen_t;
typedef unsigned int uid_t;
typedef unsigned int gid_t;
typedef int sig_atomic_t;

#define SIGPIPE 13
#define SIGHUP 1
#define SIGINT 2
#define SIGTERM 15
#define SIG_IGN ((void (*)(int))1)

struct peer_credentials {
    int pid;
    uid_t uid;
    gid_t gid;
};
struct passwd_compat {
    char *pw_name;
    char *pw_passwd;
    uid_t pw_uid;
    gid_t pw_gid;
    char *pw_gecos;
    char *pw_dir;
    char *pw_shell;
};
typedef struct { unsigned char bytes[36]; } sid_data;

extern int gsp_auth_session_create_username(const char *, sid_data *);
extern int gsp_auth_session_set_auth_type(sid_data *, const char *);
extern int gsp_auth_session_set_type(sid_data *, unsigned int);
extern int gsp_auth_session_set_cpid(sid_data *, int);
extern int gsp_auth_session_set_mpid(sid_data *, int);
extern char *gsp_auth_session_get_sid(sid_data *);
extern int gsp_auth_session_destroy(sid_data *);

extern struct passwd_compat *getpwnam(const char *);
extern unsigned int getuid(void);
extern unsigned int geteuid(void);
extern int getppid(void);
extern int getsockopt(int, int, int, void *, socklen_t *);
extern int getdtablesize(void);
extern int close(int);
extern long read(int, void *, size_t);
extern long write(int, const void *, size_t);
extern void *memset(void *, int, size_t);
extern size_t strlen(const char *);
extern void (*signal(int, void (*)(int)))(int);

static const char service_user[] = "pm3000-rest";
static const char caller_user[] = "daemon";
static volatile sig_atomic_t stop_requested;

#define SOL_SOCKET 1
/* Linux socket option numbers are architecture-specific.  PPC uses 21. */
#define SO_PEERCRED 21

static int write_all(const char *text, size_t length) {
    while (length > 0U) {
        long amount = write(1, text, length);
        if (amount <= 0) return -1;
        text += amount;
        length -= (size_t)amount;
    }
    return 0;
}

static int send_status(const char *status) {
    return write_all(status, strlen(status));
}

static int safe_sid(const char *value) {
    size_t length = 0U;
    unsigned char character;
    if (value == NULL) return 0;
    while ((character = (unsigned char)value[length]) != 0U) {
        if (length >= 128U) return 0;
        if (!((character >= 'A' && character <= 'Z') ||
              (character >= 'a' && character <= 'z') ||
              (character >= '0' && character <= '9') ||
              character == '_' || character == '-')) return 0;
        ++length;
    }
    return length > 0U;
}

static int trusted_channel(int descriptor, int parent_pid, uid_t caller_uid) {
    struct peer_credentials peer;
    socklen_t length = (socklen_t)sizeof(peer);
    memset(&peer, 0, sizeof(peer));
    return getsockopt(descriptor, SOL_SOCKET, SO_PEERCRED, &peer, &length) == 0 &&
           length == (socklen_t)sizeof(peer) && peer.pid == parent_pid &&
           peer.uid == caller_uid;
}

static void close_untrusted_descriptors(void) {
    int descriptor;
    int limit = getdtablesize();
    if (limit < 3) limit = 3;
    for (descriptor = 2; descriptor < limit; ++descriptor) (void)close(descriptor);
}

static void request_cleanup(int signal_number) {
    (void)signal_number;
    stop_requested = 1;
    (void)close(0);
}

int main(int argc, char **argv) {
    sid_data session;
    struct passwd_compat *account;
    struct passwd_compat *caller;
    char *sid;
    char ignored[16];
    int created = 0;
    int status = 3;
    int parent_pid;
    uid_t caller_uid;
    long amount;
    (void)argv;

    memset(&session, 0, sizeof(session));
    (void)signal(SIGPIPE, SIG_IGN);
    (void)signal(SIGHUP, request_cleanup);
    (void)signal(SIGINT, request_cleanup);
    (void)signal(SIGTERM, request_cleanup);
    parent_pid = getppid();
    caller_uid = getuid();
    caller = getpwnam(caller_user);
    if (argc != 1 || geteuid() != 0U || caller == NULL ||
        caller_uid != caller->pw_uid ||
        !trusted_channel(0, parent_pid, caller_uid) ||
        !trusted_channel(1, parent_pid, caller_uid)) {
        (void)send_status("ERR CHANNEL\n");
        return 2;
    }
    close_untrusted_descriptors();
    account = getpwnam(service_user);
    if (account == NULL) {
        (void)send_status("ERR USER_MISSING\n");
        return 4;
    }
    if (gsp_auth_session_create_username(service_user, &session) == -1) {
        (void)send_status("ERR SESSION_CREATE\n");
        goto cleanup;
    }
    created = 1;
    if (stop_requested) goto cleanup;
    if (gsp_auth_session_set_auth_type(&session, "local") == -1 ||
        gsp_auth_session_set_type(&session, 1U) == -1 ||
        gsp_auth_session_set_cpid(&session, parent_pid) == -1 ||
        gsp_auth_session_set_mpid(&session, parent_pid) == -1) {
        (void)send_status("ERR SESSION_CONFIG\n");
        goto cleanup;
    }
    sid = gsp_auth_session_get_sid(&session);
    if (stop_requested) goto cleanup;
    if (!safe_sid(sid)) {
        (void)send_status("ERR SESSION_SID\n");
        goto cleanup;
    }
    if (write_all("OK ", 3U) != 0 || write_all(sid, strlen(sid)) != 0 ||
        write_all("\n", 1U) != 0)
        goto cleanup;

    /* EOF means the parent completed or died. Any input is ignored. */
    do {
        amount = read(0, ignored, sizeof(ignored));
    } while (amount > 0 && !stop_requested);
    status = 0;
cleanup:
    if (created && gsp_auth_session_destroy(&session) == -1) status = 1;
    memset(&session, 0, sizeof(session));
    return status;
}
