/*
 * Build-only link interface for the PM3000 firmware libgsp_auth.so.
 *
 * This shared object is never packaged or executed. It exposes only the symbol
 * names needed to link pm3000-gsp-session-helper reproducibly in CI. At runtime
 * the helper resolves those symbols from the appliance's existing vendor
 * libgsp_auth.so.
 */

typedef struct { unsigned char bytes[36]; } sid_data;

int gsp_auth_session_create_username(const char *username, sid_data *session) {
    (void)username;
    (void)session;
    return -1;
}

int gsp_auth_session_set_auth_type(sid_data *session, const char *auth_type) {
    (void)session;
    (void)auth_type;
    return -1;
}

int gsp_auth_session_set_type(sid_data *session, unsigned int type) {
    (void)session;
    (void)type;
    return -1;
}

int gsp_auth_session_set_cpid(sid_data *session, int pid) {
    (void)session;
    (void)pid;
    return -1;
}

int gsp_auth_session_set_mpid(sid_data *session, int pid) {
    (void)session;
    (void)pid;
    return -1;
}

char *gsp_auth_session_get_sid(sid_data *session) {
    (void)session;
    return (char *)0;
}

int gsp_auth_session_destroy(sid_data *session) {
    (void)session;
    return -1;
}
