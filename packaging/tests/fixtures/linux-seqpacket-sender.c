#include <errno.h>
#include <limits.h>
#include <stdlib.h>
#include <sys/socket.h>

int main(int argc, char **argv) {
    char *end = NULL;
    long descriptor;
    const char payload[] = "sec0030-attestation";

    if (argc != 2) {
        return 64;
    }
    errno = 0;
    descriptor = strtol(argv[1], &end, 10);
    if (errno != 0 || end == argv[1] || *end != '\0' || descriptor < 0 || descriptor > INT_MAX) {
        return 64;
    }
    if (send((int)descriptor, payload, sizeof(payload) - 1, 0) < 0) {
        return errno == 0 ? 1 : errno;
    }
    return 0;
}
