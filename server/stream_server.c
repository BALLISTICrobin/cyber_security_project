/*
 * Minimal memory-backed TCP streaming server (Milestone 1).
 *
 * Streams an in-memory buffer to whoever connects, in an infinite loop,
 * until the client disconnects. The congestion-control algorithm is chosen
 * once at startup from the CC_ALGO environment variable and applied to every
 * accepted connection via setsockopt(TCP_CONGESTION) -- this is the
 * per-socket approach required when running multiple containers that share
 * one Linux kernel (see docs/Optimistic-TCP-ACK-Attacks.pdf, Ch. 8).
 *
 * Usage: stream_server [port]   (default port 5000)
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#define DEFAULT_PORT 5000
#define BUFFER_SIZE (1 << 20) /* 1 MB */

static void set_congestion_control(int fd, const char *algo) {
    if (setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, algo, strlen(algo)) < 0) {
        fprintf(stderr, "[server] WARNING: could not set congestion control to '%s': %s\n",
                algo, strerror(errno));
    } else {
        char actual[32];
        socklen_t len = sizeof(actual);
        if (getsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, actual, &len) == 0) {
            fprintf(stderr, "[server] congestion control confirmed active: '%s'\n", actual);
        }
    }
}

int main(int argc, char *argv[]) {
    int port = argc > 1 ? atoi(argv[1]) : DEFAULT_PORT;
    const char *cc_algo = getenv("CC_ALGO");
    if (!cc_algo || !*cc_algo) cc_algo = "cubic";

    int listen_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) { perror("socket"); exit(1); }

    int one = 1;
    setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port);

    if (bind(listen_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        perror("bind"); exit(1);
    }
    if (listen(listen_fd, 8) < 0) { perror("listen"); exit(1); }

    fprintf(stderr, "[server] listening on port %d, CC_ALGO=%s\n", port, cc_algo);

    static char buffer[BUFFER_SIZE];
    memset(buffer, 'X', sizeof(buffer));

    while (1) {
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);
        int client_fd = accept(listen_fd, (struct sockaddr *)&client_addr, &client_len);
        if (client_fd < 0) { perror("accept"); continue; }

        char ip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &client_addr.sin_addr, ip, sizeof(ip));
        fprintf(stderr, "[server] client connected: %s:%d\n", ip, ntohs(client_addr.sin_port));

        set_congestion_control(client_fd, cc_algo);

        long long total_sent = 0;
        while (1) {
            ssize_t n = send(client_fd, buffer, sizeof(buffer), MSG_NOSIGNAL);
            if (n <= 0) {
                fprintf(stderr, "[server] client disconnected (sent %lld bytes total)\n", total_sent);
                break;
            }
            total_sent += n;
        }
        close(client_fd);
    }

    close(listen_fd);
    return 0;
}
