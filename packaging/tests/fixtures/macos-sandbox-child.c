#include <arpa/inet.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int can_read(const char *path) {
    int descriptor = open(path, O_RDONLY);
    if (descriptor < 0) {
        return 0;
    }
    close(descriptor);
    return 1;
}

static int can_connect(const char *port_text) {
    char *end = NULL;
    long port = strtol(port_text, &end, 10);
    if (end == port_text || *end != '\0' || port < 1 || port > 65535) {
        return 0;
    }
    int descriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (descriptor < 0) {
        return 0;
    }
    struct sockaddr_in address = {0};
    address.sin_family = AF_INET;
    address.sin_port = htons((uint16_t)port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    int result = connect(descriptor, (struct sockaddr *)&address, sizeof(address)) == 0;
    close(descriptor);
    return result;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        return 64;
    }
    int file_allowed = can_read(argv[1]);
    int network_allowed = can_connect(argv[2]);
    char report[80];
    int length = snprintf(
        report,
        sizeof(report),
        "file=%s network=%s\n",
        file_allowed ? "allowed" : "denied",
        network_allowed ? "allowed" : "denied");
    if (length < 0 || length >= (int)sizeof(report)) {
        return 70;
    }
    char *end = NULL;
    long output = strtol(argv[3], &end, 10);
    if (end == argv[3] || *end != '\0' || output < 0) {
        return 64;
    }
    if (write((int)output, report, (size_t)length) != length) {
        return 70;
    }
    return 0;
}
