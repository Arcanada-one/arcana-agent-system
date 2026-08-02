#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

int main(int argc, char **argv) {
    if (argc != 4) {
        return 64;
    }
    int channel[2];
    if (pipe(channel) != 0) {
        return 70;
    }
    pid_t child = fork();
    if (child < 0) {
        return 70;
    }
    if (child == 0) {
        close(channel[0]);
        if (setsid() < 0) {
            _exit(70);
        }
        pid_t grandchild = fork();
        if (grandchild < 0) {
            _exit(70);
        }
        if (grandchild > 0) {
            _exit(0);
        }
        char descriptor[32];
        snprintf(descriptor, sizeof(descriptor), "%d", channel[1]);
        execl(argv[1], argv[1], argv[2], argv[3], descriptor, NULL);
        _exit(errno == 0 ? 70 : errno);
    }
    close(channel[1]);
    int status = 0;
    if (waitpid(child, &status, 0) != child || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
        return 70;
    }
    char report[80] = {0};
    ssize_t length = read(channel[0], report, sizeof(report) - 1);
    close(channel[0]);
    if (length <= 0) {
        return 70;
    }
    if (strcmp(report, "file=denied network=denied\n") != 0) {
        fprintf(stderr, "sandboxed descendant escaped: %s", report);
        return 78;
    }
    printf("%s", report);
    return 0;
}
