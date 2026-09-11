/*
 * defense_server -- streaming server with Sherwood's randomly-skipped-segment
 * test (Milestone 4 defense).
 *
 * The optimistic-ACK attack works because a normal TCP sender trusts ACKs. This
 * server catches a lying receiver directly: every so often it *skips* a segment
 * -- it advances its send sequence past a small gap WITHOUT transmitting those
 * bytes -- and remembers the hole. Then:
 *   - an HONEST receiver never got the skipped bytes, so its cumulative ACK
 *     cannot advance past the hole; it stalls there until we retransmit;
 *   - a MISBEHAVING optimistic receiver acknowledges data it never received, so
 *     it ACKs straight past the hole -- which is impossible for an honest peer
 *     and proves it is lying. The server logs it and RSTs the flow.
 * Skipped bytes are retransmitted after a short delay, so honest clients are
 * never harmed by the test.
 *
 * Because it controls its own TCP sequence numbers, this is a raw-socket server
 * (a normal kernel socket cannot leave a hole in the byte stream). It drives the
 * whole connection from raw sockets, so it suppresses the kernel's RST for its
 * listen port with an iptables rule (needs NET_ADMIN + NET_RAW + iptables; all
 * granted to the server container). It streams over a lossless path, so the only
 * retransmits it needs are its own deliberate skips.
 *
 * Build: gcc -O2 -Wall -o defense_server defense_server.c
 * Usage: DEFENSE=on defense_server [port]     (default port 5000)
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
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define SEQ_LT(a, b) ((int32_t)((a) - (b)) < 0)
#define SEQ_GT(a, b) ((int32_t)((a) - (b)) > 0)
#define SEQ_GEQ(a, b) ((int32_t)((a) - (b)) >= 0)

#define MSS 1460
#define WIN 65535           /* advertised window (no scaling, keeps it simple) */
#define INFLIGHT (256 * 1024)   /* how far ahead of snd_una we let ourselves send */
#define SKIP_EVERY_S 0.5    /* inject a skip roughly this often */
#define SKIP_RETX_S 0.2     /* retransmit a skipped segment after this long */
#define MAX_SKIPS 16

static volatile sig_atomic_t g_running = 1;
static void on_signal(int sig) { (void)sig; g_running = 0; }

static uint16_t checksum16(const void *data, size_t len) {
    const uint16_t *p = data;
    uint32_t sum = 0;
    while (len > 1) { sum += *p++; len -= 2; }
    if (len) sum += *(const uint8_t *)p;
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    return (uint16_t)~sum;
}

static uint16_t tcp_checksum(uint32_t src, uint32_t dst,
                             const void *tcp, size_t tcp_len) {
    struct {
        uint32_t src, dst; uint8_t zero, proto; uint16_t len;
    } __attribute__((packed)) ph = { src, dst, 0, IPPROTO_TCP, htons((uint16_t)tcp_len) };
    size_t buflen = sizeof(ph) + tcp_len;
    uint8_t *buf = malloc(buflen);
    memcpy(buf, &ph, sizeof(ph));
    memcpy(buf + sizeof(ph), tcp, tcp_len);
    uint16_t c = checksum16(buf, buflen);
    free(buf);
    return c;
}

static double now_s(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec + ts.tv_nsec / 1e9;
}

struct conn {
    uint32_t src_ip, dst_ip;   /* server, client (network order) */
    uint16_t src_port, dst_port;
};

/* Build IPv4+TCP (+ optional payload/options) into buf; return total length. */
static size_t build_packet(uint8_t *buf, const struct conn *c,
                           uint32_t seq, uint32_t ack, uint8_t flags, uint16_t win,
                           const uint8_t *opts, size_t optlen,
                           const uint8_t *payload, size_t paylen) {
    struct iphdr *ip = (struct iphdr *)buf;
    struct tcphdr *tcp = (struct tcphdr *)(buf + sizeof(*ip));
    size_t tcp_len = sizeof(*tcp) + optlen;
    size_t tot = sizeof(*ip) + tcp_len + paylen;

    memset(buf, 0, sizeof(*ip) + tcp_len);
    ip->ihl = 5; ip->version = 4; ip->tot_len = htons((uint16_t)tot);
    ip->id = htons((uint16_t)(seq ^ ack)); ip->frag_off = htons(0x4000);
    ip->ttl = 64; ip->protocol = IPPROTO_TCP;
    ip->saddr = c->src_ip; ip->daddr = c->dst_ip;
    ip->check = checksum16(ip, sizeof(*ip));

    tcp->source = htons(c->src_port); tcp->dest = htons(c->dst_port);
    tcp->seq = htonl(seq); tcp->ack_seq = htonl(ack);
    tcp->doff = (uint16_t)(tcp_len / 4);
    tcp->fin = (flags & TH_FIN) ? 1 : 0; tcp->syn = (flags & TH_SYN) ? 1 : 0;
    tcp->rst = (flags & TH_RST) ? 1 : 0; tcp->psh = (flags & TH_PUSH) ? 1 : 0;
    tcp->ack = (flags & TH_ACK) ? 1 : 0; tcp->window = htons(win);
    if (opts && optlen) memcpy((uint8_t *)tcp + sizeof(*tcp), opts, optlen);
    if (payload && paylen) memcpy((uint8_t *)tcp + tcp_len, payload, paylen);
    tcp->check = tcp_checksum(c->src_ip, c->dst_ip, tcp, tcp_len + paylen);
    return tot;
}

static void send_pkt(int fd, const struct conn *c, const uint8_t *buf, size_t len) {
    struct sockaddr_in to = {0};
    to.sin_family = AF_INET; to.sin_addr.s_addr = c->dst_ip; to.sin_port = c->dst_port;
    sendto(fd, buf, len, 0, (struct sockaddr *)&to, sizeof(to));
}

struct skip { uint32_t start, end; double retx_at; int active; };

int main(int argc, char **argv) {
    int port = argc > 1 ? atoi(argv[1]) : 5000;
    const char *def = getenv("DEFENSE");
    int defense_on = def && (!strcmp(def, "on") || !strcmp(def, "1"));

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    srand((unsigned)(getpid() ^ (unsigned)time(NULL)));

    int sfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sfd < 0) { perror("socket(send)"); return 1; }
    int one = 1;
    if (setsockopt(sfd, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        perror("IP_HDRINCL"); return 1;
    }
    int rfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (rfd < 0) { perror("socket(recv)"); return 1; }

    /* Suppress the kernel's RSTs for our listen port (it has no socket there). */
    char cmd[160];
    snprintf(cmd, sizeof(cmd),
             "iptables -A OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP 2>/dev/null", port);
    if (system(cmd) != 0)
        fprintf(stderr, "[defense] WARNING: could not add iptables RST rule\n");

    fprintf(stderr, "[defense] listening on port %d, skip-test defense %s\n",
            port, defense_on ? "ENABLED" : "disabled");

    static uint8_t sndbuf[1 << 20];   /* 1 MB payload source */
    memset(sndbuf, 'X', sizeof(sndbuf));
    uint8_t pkt[2048];

    while (g_running) {
        /* ---- wait for a client SYN ---- */
        struct conn c = {0};
        uint32_t client_isn = 0;
        int have_client = 0;
        while (g_running && !have_client) {
            struct pollfd pfd = { rfd, POLLIN, 0 };
            if (poll(&pfd, 1, 200) <= 0) continue;
            ssize_t n = recv(rfd, pkt, sizeof(pkt), 0);
            if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            struct iphdr *ip = (struct iphdr *)pkt;
            struct tcphdr *tcp = (struct tcphdr *)(pkt + ip->ihl * 4);
            if (ntohs(tcp->dest) != port) continue;
            if (tcp->syn && !tcp->ack) {
                c.src_ip = ip->daddr; c.dst_ip = ip->saddr;
                c.src_port = port; c.dst_port = ntohs(tcp->source);
                client_isn = ntohl(tcp->seq);
                have_client = 1;
            }
        }
        if (!g_running) break;

        char cip[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &c.dst_ip, cip, sizeof(cip));
        fprintf(stderr, "[defense] client %s:%u connected\n", cip, c.dst_port);

        /* ---- handshake: SYN-ACK, then wait for the client's ACK ---- */
        uint32_t isn = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
        uint8_t synopt[4] = { 2, 4, 0x05, 0xb4 };   /* MSS 1460 */
        size_t len = build_packet(pkt, &c, isn, client_isn + 1, TH_SYN | TH_ACK,
                                  WIN, synopt, sizeof(synopt), NULL, 0);
        uint32_t snd_una = isn + 1, snd_nxt = isn + 1;
        int established = 0;
        double hs_deadline = now_s() + 5.0;
        while (g_running && !established && now_s() < hs_deadline) {
            send_pkt(sfd, &c, pkt, len);
            struct pollfd pfd = { rfd, POLLIN, 0 };
            if (poll(&pfd, 1, 200) <= 0) continue;
            ssize_t n = recv(rfd, pkt, sizeof(pkt), 0);
            if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) continue;
            struct iphdr *ip = (struct iphdr *)pkt;
            struct tcphdr *tcp = (struct tcphdr *)(pkt + ip->ihl * 4);
            if (ip->saddr != c.dst_ip || ntohs(tcp->source) != c.dst_port ||
                ntohs(tcp->dest) != port) continue;
            if (tcp->rst) { established = -1; break; }
            if (tcp->ack && !tcp->syn) established = 1;
        }
        if (established != 1) { fprintf(stderr, "[defense] handshake failed\n"); continue; }

        /* ---- stream with the skip-test ---- */
        struct skip skips[MAX_SKIPS] = {0};
        double t0 = now_s(), next_skip = t0 + 1.0;   /* let it ramp for 1s first */
        uint16_t client_win = WIN;
        long long delivered = 0;
        int detected = 0;
        /* Pace egress modestly so ACKs are drained promptly and the skip-test
         * fires within milliseconds; this is a defence demo, not a throughput
         * test, so a normal server rate is plenty. */
        const double PACE_BPS = 20e6 / 8.0;
        double last_pace = now_s();
        double budget = 0;

        while (g_running && !detected) {
            /* drain ACKs from the client */
            struct pollfd pfd = { rfd, POLLIN, 0 };
            int pr = poll(&pfd, 1, 1);
            while (pr > 0) {
                ssize_t n = recv(rfd, pkt, sizeof(pkt), MSG_DONTWAIT);
                if (n < (ssize_t)(sizeof(struct iphdr) + sizeof(struct tcphdr))) break;
                struct iphdr *ip = (struct iphdr *)pkt;
                struct tcphdr *tcp = (struct tcphdr *)(pkt + ip->ihl * 4);
                if (ip->saddr != c.dst_ip || ntohs(tcp->source) != c.dst_port ||
                    ntohs(tcp->dest) != port) continue;
                if (tcp->rst || tcp->fin) { detected = -1; break; }
                if (tcp->ack) {
                    uint32_t ack = ntohl(tcp->ack_seq);
                    client_win = ntohs(tcp->window);
                    if (client_win < MSS) client_win = MSS;
                    /* THE TEST: did this ACK cover a hole we deliberately left? */
                    if (defense_on) {
                        for (int i = 0; i < MAX_SKIPS; i++) {
                            if (skips[i].active && SEQ_GT(ack, skips[i].start)) {
                                fprintf(stderr,
                                    "[defense] OPTIMISTIC ACK DETECTED: client acked %u, "
                                    "past skipped segment [%u,%u) it never received -- "
                                    "resetting flow\n",
                                    ack, skips[i].start, skips[i].end);
                                detected = 1;
                                break;
                            }
                        }
                    }
                    if (SEQ_GT(ack, snd_una)) snd_una = ack;
                }
                if (detected) break;
            }
            if (detected) break;

            double t = now_s();
            /* retransmit any skip whose grace period has elapsed (honest clients) */
            for (int i = 0; i < MAX_SKIPS; i++) {
                if (skips[i].active && t >= skips[i].retx_at) {
                    uint32_t off = skips[i].start - (isn + 1);
                    len = build_packet(pkt, &c, skips[i].start, client_isn + 1,
                                       TH_ACK | TH_PUSH, WIN, NULL, 0,
                                       sndbuf + (off % (sizeof(sndbuf) - MSS)), MSS);
                    send_pkt(sfd, &c, pkt, len);
                    skips[i].active = 0;
                }
            }

            /* time to inject a new skip? */
            if (defense_on && t >= next_skip) {
                next_skip = t + SKIP_EVERY_S;
                for (int i = 0; i < MAX_SKIPS; i++) {
                    if (!skips[i].active) {
                        skips[i].start = snd_nxt; skips[i].end = snd_nxt + MSS;
                        skips[i].retx_at = t + SKIP_RETX_S; skips[i].active = 1;
                        snd_nxt += MSS;   /* advance past the hole WITHOUT sending it */
                        break;
                    }
                }
            }

            /* send new data, inside the receiver window and the pacing budget */
            budget += (t - last_pace) * PACE_BPS;
            last_pace = t;
            if (budget > 64 * 1024) budget = 64 * 1024;
            uint32_t win_edge = snd_una + (client_win < INFLIGHT ? client_win : INFLIGHT);
            while (g_running && SEQ_LT(snd_nxt, win_edge) && budget >= MSS) {
                uint32_t off = snd_nxt - (isn + 1);
                len = build_packet(pkt, &c, snd_nxt, client_isn + 1, TH_ACK | TH_PUSH,
                                   WIN, NULL, 0,
                                   sndbuf + (off % (sizeof(sndbuf) - MSS)), MSS);
                send_pkt(sfd, &c, pkt, len);
                snd_nxt += MSS; delivered += MSS; budget -= MSS;
            }
            usleep(500);
        }

        if (detected == 1)
            fprintf(stderr, "[defense] flow reset after %lld bytes\n", delivered);
        else
            fprintf(stderr, "[defense] client gone after %lld bytes\n", delivered);

        /* RST the flow closed */
        len = build_packet(pkt, &c, snd_nxt, client_isn + 1, TH_RST | TH_ACK, 0,
                           NULL, 0, NULL, 0);
        send_pkt(sfd, &c, pkt, len);
    }

    snprintf(cmd, sizeof(cmd),
             "iptables -D OUTPUT -p tcp --sport %d --tcp-flags RST RST -j DROP 2>/dev/null", port);
    if (system(cmd) != 0) { /* best effort */ }
    close(sfd); close(rfd);
    return 0;
}
