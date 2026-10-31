#define setsockopt pm3000_test_setsockopt
#include "../src/tls.c"
#undef setsockopt

#include <netinet/in.h>

static int timeout_calls;
static int timeout_failure;
static unsigned int timeout_options;

int pm3000_test_setsockopt(int descriptor, int level, int option,
                           const void *value, socklen_t length)
{
    static const unsigned char expected[8] = {
        0x00U, 0x00U, 0x00U, 0x09U,
        0x00U, 0x00U, 0x00U, 0x00U
    };
    (void)descriptor;
    if (level != 1) return -1;
    ++timeout_calls;
    if (option == 18) timeout_options |= 1U;
    else if (option == 19) timeout_options |= 2U;
    else {
        fprintf(stderr, "target timeout ABI mismatch: option=%d expected=18/19\n",
                option);
        timeout_failure = 1;
    }
    if (length != (socklen_t)sizeof(expected) ||
        memcmp(value, expected, sizeof(expected)) != 0) {
        fprintf(stderr, "target timeout ABI mismatch: length=%u expected=8\n",
                (unsigned int)length);
        timeout_failure = 1;
    }
    return 0;
}

int main(void)
{
    int listener;
    int connected;
    struct sockaddr_in address;
    socklen_t address_length = (socklen_t)sizeof(address);

    listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (listener < 0) return 2;
    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    address.sin_port = 0;
    if (bind(listener, (struct sockaddr *)&address, sizeof(address)) != 0 ||
        listen(listener, 1) != 0 ||
        getsockname(listener, (struct sockaddr *)&address, &address_length) != 0) {
        close(listener);
        return 3;
    }
    connected = tcp_connect("127.0.0.1", (unsigned int)ntohs(address.sin_port), 9U);
    if (connected >= 0) close(connected);
    close(listener);
    if (connected < 0 || timeout_calls != 2 || timeout_options != 3U ||
        timeout_failure) return 1;
    if (write(STDOUT_FILENO, "tls.target_timeout_abi.complete=yes\n", 36U) != 36)
        return 4;
    return 0;
}
