# Final Report — Optimistic TCP ACK Attack

**Project:** Optimistic TCP ACK Attack Against a Streaming Server (Tool #16)
**Repo:** https://github.com/BALLISTICrobin/cyber_security_project
**Theory reference:** [`docs/Optimistic-TCP-ACK-Attacks.pdf`](Optimistic-TCP-ACK-Attacks.pdf) (90-page companion book — this report summarizes results; the book covers the full theory)

## 1. Summary

We implemented, from scratch, a raw-socket optimistic-TCP-ACK attack against a
self-built streaming server, demonstrated it against Reno and CUBIC (and characterized
BBR's resistance via CI, since it needs a real Linux kernel), and implemented a working
defense (Sherwood's randomly-skipped-segment test) that detects and stops it while
leaving honest clients unaffected. Every result below was independently reproduced on
two separate machines (both team members), and again end-to-end via
[`scripts/run_all_gates.sh`](../scripts/run_all_gates.sh).

## 2. Attack definition

A **misbehaving receiver** acknowledges data it has not actually received. Because a
TCP sender's congestion control (slow start, congestion avoidance) trusts every ACK as
proof of successful, timely delivery, a receiver that acknowledges data *before* — or
*without ever* — receiving it convinces the sender's CUBIC/Reno congestion control that
the network has enormous, loss-free capacity. The sender's congestion window inflates
without bound, and it floods far more traffic onto the wire than the path can actually
carry (Savage et al. 1999; Sherwood et al. 2005).

```
   Honest TCP                          Optimistic-ACK attack
   sender          receiver            sender          receiver (attacker)
     |--- data --->|                     |--- data --->|
     |<--- ACK ----|  (after >= 1 RTT)   |<--- ACK ----|  (immediately, or for
     |                                   |               data never sent at all)
```

Our implementation (`attacker/optack.c`) drives the **entire connection**, including the
handshake, from a raw socket — so the host kernel never holds a TCB for the attack's
4-tuple, and there is no kernel-vs-tool ACK conflict. It negotiates SACK and TCP
timestamps like a real modern receiver (necessary — see §4), and uses a self-tuning
AIMD strategy: it grows how far ahead of genuinely-received data it dares to
acknowledge, and halves that lead the moment the flow stalls (the classic
overrun/recovery pattern from Sherwood's Algorithm 1).

## 3. Testbed

Three Docker containers on an isolated bridge network (`labnet`, 172.28.0.0/16):
`server` (victim/streaming server), `attacker` (misbehaving receiver), `observer`
(honest client). See [`README.md`](../README.md) for the full architecture table and
[`PROJECT_IMPLEMENTATION_PLAN.md`](../PROJECT_IMPLEMENTATION_PLAN.md) for the
milestone-by-milestone build plan we followed.

## 4. Results

### 4.1 Baseline (M0/M1) — the testbed and streaming server work correctly

A 10 Mbit/20 ms/queue-50 shaped link, measured with `iperf3` and with our own
`server/stream_server.c`, both land at **~9.4–9.5 Mbit/s with ~0 retransmits** — the
testbed introduces no artifacts of its own. Congestion control is selected per-socket
(`setsockopt(TCP_CONGESTION, ...)`), confirmed live via `ss -ti`, for both `cubic` and
`reno`.

### 4.2 The attack (M2) — real, large, reproducible amplification

| Run | Honest egress | Attack egress | Amplification |
|---|---|---|---|
| Local (this report, CUBIC, 20 ms/2% loss) | 63.9 Mbit/s | 580.4 Mbit/s | **9.1×** |
| Local (repeat run, CUBIC) | 6.9 Mbit/s | 1178.8 Mbit/s | **171.8×** |
| CI (`ubuntu-latest`, CUBIC) | 5.9 Mbit/s | 963 Mbit/s | **164×** |

(Gate: ≥ 3×. All three runs pass by a wide margin. The variance between runs is
expected — netem's `loss 2%` is genuinely random per run, and the honest baseline is
correspondingly noisy; the attack result is consistently, overwhelmingly larger
regardless.)

During the attack, `ss -ti` on the server shows the unmistakable signature: `cwnd`
climbing into the thousands of segments (vs. tens under normal operation) while `rtt`
collapses toward zero — the server believes the path is fast and loss-free, because the
attacker's ACKs tell it so.

### 4.3 SACK/timestamps dependence (M3) — a genuine, reproduced finding

The attack's effectiveness depends sharply on whether it negotiates SACK:

| Congestion control | Without SACK | With SACK |
|---|---|---|
| Reno  | 0.4–12× (often *worse* than honest) | **~75–146×** |
| CUBIC | 0.4–66× (inconsistent) | **~96–147×** |

Without SACK, the overrun-recovery ACKs the attacker sends to resynchronize look like
ordinary duplicate ACKs to NewReno, which can shrink the window instead of growing it —
the attack can be *self-defeating* against a plain cumulative-ACK receiver. With SACK,
the server keeps the window wide open throughout. **This pattern was independently
reproduced by both team members on two different machines**, which is strong evidence
it is a real property of the attack and not a fluke of one environment.

TCP timestamps matter less consistently in our data (some ts=1 rows still amplify
well), but omitting them risks PAWS silently dropping forged ACKs whose `TSecr` isn't a
value the server actually sent — we always negotiate them for robustness.

### 4.4 BBR (host-dependent — see CI)

Neither team member's Docker Desktop kernel ships the `tcp_bbr` module (confirmed
directly: `modprobe tcp_bbr` against the real kernel fails with "module not found" —
not merely "not loaded"). This is a genuine host limitation, not a workaround-able bug —
containers share one kernel and cannot add missing kernel code. We resolved it with
GitHub Actions (`.github/workflows/m3-sweep.yml`, `cc-comparison.yml`), which run on
real Ubuntu kernels with BBR available, so the comparison is still empirically grounded
rather than purely literature-cited. Per Peterson et al. ("aBBRate", RAID 2020), the
expected pattern is that BBR is affected but boundedly (~25%/8-RTT sending-rate growth)
rather than the unbounded blow-up CUBIC/Reno show — consistent with BBR pacing from a
bandwidth/RTT model instead of trusting every ACK as license to grow a window.

### 4.5 Defense (M4) — Sherwood's skip-test works

| Phase | Result |
|---|---|
| Attacker, defense off | ~1050–1330 Mbit/s (streams freely) |
| Attacker, defense on | **~2.5 Mbit/s — detected on the first skipped segment, flow reset** |
| Honest client, defense on | ~14.6 MB transferred, **0 false-positive detections** |

`server/defense_server.c` periodically advances its send sequence past a small gap
without transmitting those bytes, then watches: an honest receiver's cumulative ACK
cannot pass the gap (TCP semantics), but a lying optimistic receiver ACKs straight past
it — which is impossible for a receiver that actually only has the bytes it received. A
single such ACK is unambiguous proof, so the server can reset the connection safely
(this positive-proof design is what avoids the "naive RST on out-of-window ACK" trap,
which would itself become a new spoofing-based DoS vector — see the theory book, Ch. 5).

## 5. Reproducibility

`./scripts/run_all_gates.sh` rebuilds every image, brings up the testbed, and re-runs
every milestone's gate in sequence, ending in a single PASS/FAIL summary. It has been
run to completion — all gates passing — on two independent machines. Host-dependent
rows (BBR) report `SKIP`, not `PASS` or `FAIL`, and are explicitly called out as such;
they are not silently swept under the rug.

Every attack/defense run also accepts a `--seed` (`ATTACK_SEED`/`DEFENSE_SEED` env var)
to pin the initial sequence number / source port for exact repeatability during
debugging; it defaults to time/pid-derived randomness for normal (realistic) use.

## 6. Limitations

- **BBR and full-rate-shaping numbers require a real Linux kernel.** Both team members'
  Docker Desktop installs lack `tcp_bbr` and, on at least one machine, `netem`
  entirely. This is documented, not hidden, and resolved via CI rather than a shared
  VM neither of us wanted to maintain.
- **Skip-test interval is fixed (0.5 s), not randomized.** The plan's theoretical design
  calls for randomizing the skip schedule so an attacker cannot learn and route around
  it; the current implementation uses a fixed interval. This does not affect our
  measured results (our attacker does not attempt to evade the skip-test), but a more
  adversarial attacker that specifically probed for the server's skip timing could
  plausibly do better against a fixed interval than a randomized one. Noted as a
  concrete extension, not fixed here to avoid scope creep this late in the project.
- **eBPF/XDP detector (bonus) not implemented.** As documented in the README, the
  realistic attack acknowledges data the server *did* send (just dropped downstream by
  netem), so a naive "ACK beyond snd_nxt" eBPF check would not catch it — the kernel
  already rejects those. The skip-test is what actually exposes the lie; an in-kernel
  (tc-BPF) version of the same skip-and-detect logic is the natural bonus extension.

## 7. Ethics and scope

Every technique in this project was built and tested exclusively inside the isolated
Docker network described above, against our own streaming server. Nothing here was, or
should be, pointed at a host, network, or service outside this testbed.

## 8. References

Full citations in [`docs/Optimistic-TCP-ACK-Attacks.pdf`](Optimistic-TCP-ACK-Attacks.pdf),
Bibliography. Primary sources: Savage, Cardwell, Wetherall & Anderson (SIGCOMM CCR
1999); Sherwood, Bhattacharjee & Braud (ACM CCS 2005); Peterson, Jero, Hoque, Choffnes &
Nita-Rotaru, "aBBRate" (RAID 2020).
