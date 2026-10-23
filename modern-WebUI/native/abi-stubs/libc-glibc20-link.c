/*
 * Build-only GLIBC_2.0 link interface for pm3000-gsp-session-helper.
 *
 * This shared object is never packaged or executed. Its version script pins
 * the helper's libc imports to the firmware-compatible GLIBC_2.0 ABI. Runtime
 * resolution uses the appliance's existing /lib/libc.so.6.
 */

typedef unsigned int size_t;
typedef unsigned int socklen_t;
typedef void (*signal_handler)(int);

void *getpwnam(const char *name) { (void)name; return (void *)0; }
unsigned int getuid(void) { return 0U; }
unsigned int geteuid(void) { return 0U; }
int getppid(void) { return 0; }
int getsockopt(int fd, int level, int option, void *value, socklen_t *length) {
    (void)fd; (void)level; (void)option; (void)value; (void)length; return -1;
}
int getdtablesize(void) { return 0; }
int close(int fd) { (void)fd; return -1; }
long read(int fd, void *buffer, size_t length) {
    (void)fd; (void)buffer; (void)length; return -1;
}
long write(int fd, const void *buffer, size_t length) {
    (void)fd; (void)buffer; (void)length; return -1;
}
void *memset(void *buffer, int value, size_t length) {
    (void)value; (void)length; return buffer;
}
size_t strlen(const char *text) { (void)text; return 0U; }
signal_handler signal(int number, signal_handler handler) {
    (void)number; return handler;
}
