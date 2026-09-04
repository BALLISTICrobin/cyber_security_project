# Optimistic TCP ACK Attack — Project Implementation Plan

**Team size:** 2 (you + 1 teammate)
**Environment:** Docker / Docker Compose (shared, reproducible dev + test environment for both of you)
**Companion reference:** `tcp_optimistic_ack_book/Optimistic-TCP-ACK-Attacks.pdf` — the theory book. This document is the *build plan*; the book is the *why*.

This plan intentionally has **few milestones** (6, M0–M5). Each one ends with a hard, runnable **verification gate** — a specific command or test you both run before moving on. Do not start the next milestone until the current gate passes. That's what keeps two people on Docker from drifting into "works on my machine."

---

## 0. Team & Repo Conventions (decide before M0)

| Item | Decision |
|---|---|
| Repo | One shared Git repo, `main` branch protected; work on `feat/*` branches, PR + review before merge |
| Ownership | Member A = attacker tooling + packet crafting + eBPF detector. Member B = streaming server + defenses (skip-test) + dashboard/harness. Both review each other's PRs — nobody works fully isolated on a 2-person team. |
| Environment parity | **Nobody installs anything on the host.** Everything relevant (server, attacker, sniffer, dashboard) runs inside Docker containers defined in `docker-compose.yml`, checked into the repo. If it's not in Compose, it doesn't count as "working." |
| Directory layout | `/server`, `/attacker`, `/defense`, `/harness`, `/docker`, `/docs`, `/reports` — one Dockerfile per component that needs one |
| Reproducibility rule | Every milestone's gate must pass via `docker compose up` + one documented command, from a clean clone, by *both* teammates independently |

---

## 1. Docker Architecture (fixed for the whole project)

```
                 docker-compose network: labnet (bridge)
   ┌───────────────┐        ┌───────────────┐        ┌───────────────┐
   │   attacker     │        │    server      │        │   observer     │
   │ (Scapy proto + │◄──────►│ (streaming     │◄──────►│ (tcpdump,      │
   │  C raw-socket  │  TCP   │  server, CC    │        │  Grafana/      │
   │  attack tool)  │        │  selectable,   │        │  Prometheus,   │
   │ cap: NET_RAW,  │        │  eBPF defense) │        │  honest client)│
   │      NET_ADMIN │        │ cap: NET_ADMIN,│        │                │
   └───────────────┘        │  SYS_ADMIN,BPF │        └───────────────┘
                             └───────────────┘
```

**Docker-specific realities to design around from day 1** (these are the #1 source of wasted time if discovered late):

- **Congestion control must be set per-socket**, not via host-wide `sysctl`, because all containers share the host kernel. The server always calls `setsockopt(fd, IPPROTO_TCP, TCP_CONGESTION, "cubic"/"reno"/"bbr", …)` per connection — never rely on changing the *system* default.
- **Raw sockets** (the attack tool) need `cap_add: [NET_RAW]` on the `attacker` service — not full `privileged: true`.
- **Traffic shaping** (`tc`/`netem` for the bottleneck link) needs `cap_add: [NET_ADMIN]` and is applied to the container's own `eth0` from inside the container, or on the host-side veth from outside — pick one approach and document it in `/docker/README.md`.
- **eBPF/XDP** inside Docker (bridge network, veth pairs) has **no native driver support**, so it always runs in generic/SKB mode, same caveat as VirtualBox in the book (Ch. 15). Functional correctness can be demonstrated in Docker; the "**<X% overhead**" number for the report/CV must be measured on the bare host or a Mininet/bare-metal box outside Docker, and the plan must say so explicitly in the final report.
- **Two-stack conflict** (Ch. 6, §6.1 of the book): if the attacker container ever opens the connection with a normal kernel socket *and* forges ACKs on a raw socket for the same 4-tuple, the two will fight. Decide once, in M2: drive the whole connection (including the handshake) from the raw socket, so no kernel TCB exists for that 4-tuple on the attacker side.

---

## Milestone Overview

| # | Milestone | Roughly | Rubric tie-in |
|---|---|---|---|
| M0 | Dockerized testbed + baseline | Week 1–2 | — (infrastructure) |
| M1 | Streaming server + CC instrumentation | Week 2–3 | — |
| M2 | Working optimistic-ACK attack (CUBIC) | Week 4–6 | Design Report |
| M3 | Multi-CC matrix + live dashboard | Week 7–8 | Design Report |
| M4 | Defenses: skip-test + eBPF detector | Week 9–11 | +10% bonus |
| M5 | Reproducibility package + final report/demo | Week 12–14 | Final Report + Demo |

Six milestones, each with one non-negotiable gate. If a gate fails, you fix it before writing a single line of the next milestone — that's the whole point of keeping the milestone count small.

---

## M0 — Dockerized Testbed + Baseline

**Goal:** Three containers that can talk to each other over a shaped, realistic link, with a measured baseline.

**Tasks**
- [ ] `docker-compose.yml` defining `attacker`, `server`, `observer` on a custom bridge network `labnet`
- [ ] Base Dockerfiles (Debian/Ubuntu slim + build-essential, iproute2, tcpdump, iperf3, python3-scapy)
- [ ] Apply `tc netem` shaping between attacker↔server (e.g. 10 Mbps, 20 ms delay, queue limit 50) — scripted, not manual
- [ ] `observer` runs `tcpdump` to a shared Docker volume; `iperf3` baseline test between attacker and server

**Verification gate (both teammates run this independently, from a clean `git clone`):**
```bash
docker compose up -d
docker compose exec server iperf3 -s -D
docker compose exec attacker iperf3 -c server -t 15 -J > baseline.json
# PASS = baseline.json shows stable throughput consistent with the configured 10Mbit/20ms link,
# and docker compose exec attacker tc qdisc show dev eth0 shows the netem qdisc applied
```
**Definition of done:** both teammates get matching baseline numbers (±10%) on their own machines from the same Compose file.

---

## M1 — Streaming Server + CC Instrumentation

**Goal:** Your own TCP streaming server, containerized, with selectable congestion control and live `ss -ti` visibility.

**Tasks**
- [ ] Custom TCP streaming server (memory-backed buffer, per Ch. 17 of the book) in the `server` container, CC algorithm chosen via `CC_ALGO` env var → `setsockopt(TCP_CONGESTION)`
- [ ] A trivial streaming client in the `attacker`/`observer` image for honest baseline pulls
- [ ] Logging script: periodic `ss -ti` snapshots to CSV inside the container, mounted out via volume

**Verification gate:**
```bash
CC_ALGO=cubic docker compose up -d server
docker compose exec observer bash -c "curl-equivalent-client | tee /data/pull.log"
docker compose exec server ss -ti dst observer
# PASS = ss output shows the "cubic" congestion algorithm active, cwnd climbing then
# stabilizing normally (no attack running), stream completes without errors
```
Repeat once for `reno` and once for `bbr` (requires `tcp_bbr` module + `fq` qdisc available on the **host** — containers share the host kernel's compiled-in CC modules).

**Definition of done:** all three algorithms stream cleanly and show up correctly in `ss -ti` with zero attack running — this is your control group for every later comparison.

---

## M2 — Working Optimistic-ACK Attack (CUBIC)

**Goal:** A real, repeatable cwnd-inflation attack against your own server on CUBIC. This is the make-or-break milestone — everything downstream depends on it.

**Tasks**
- [ ] Python/Scapy prototype in `attacker` container: validate packet format, sequence tracking (Ch. 6)
- [ ] Port to raw-socket C tool (Ch. 6–7): checksums, ack-advance loop (Sherwood's Algorithm 1), overrun detection/recovery, TCP timestamp echoing
- [ ] Decide and implement the handshake ownership approach from §1 above (raw-socket-driven, no kernel TCB conflict)

**Verification gate:**
```bash
docker compose run --rm attacker ./attack --target server --port 5000
docker compose exec server ss -ti dst attacker
# PASS = cwnd on the server climbs well past its normal ceiling and keeps growing
#        (no plateau), rtt/rto visibly collapse toward ~0, and egress throughput on the
#        server measurably exceeds the M0 baseline by a documented factor
```
**Definition of done (hard threshold, matches the book's Ch. 19 benchmark):** a **repeatable ≥3× egress inflation vs. the M1 CUBIC baseline**, reproducible by both teammates from the same container image.

**Fallback if this gate isn't met after a fixed time-box (~1 week):** implement the "lazy" optimistic-ACK variant (Ch. 7 of the book — ACK only genuinely-received data, never signal loss). It's a smaller result but avoids the sync problem entirely and still proves non-responsive-flow DoS. Don't silently keep debugging past the time-box — switch and keep moving.

---

## M3 — Multi-CC Matrix + Live Dashboard

**Goal:** The project's main "wow factor" — quantified comparison across Reno/CUBIC/BBR, visualized.

**Tasks**
- [ ] Automated sweep script (runs inside a `harness` one-off container or the `observer`): CC algorithm × timestamps on/off × SACK on/off, each run logging peak cwnd / amplification factor to JSON
- [ ] Dashboard: either a `grafana` + `prometheus` service added to `docker-compose.yml` scraping a small metrics exporter in the `server` container, or a simpler live-`matplotlib` script in `observer` — pick one, don't build both
- [ ] Dashboard shows at minimum: cwnd over time, egress rate, and the ACKed-vs-genuinely-delivered byte gap

**Verification gate:**
```bash
docker compose run --rm harness python sweep.py --out sweep_results.json
# PASS = sweep_results.json has one row per (cc, timestamps, sack) combination,
#        CUBIC/Reno rows show unbounded/large amplification, BBR rows show
#        bounded growth (~consistent with the aBBRate ~25%/8-RTT finding),
#        and the dashboard renders live during a fresh attack run
```
**Definition of done:** both teammates can independently run `sweep.py` and get the same qualitative pattern (CUBIC/Reno vulnerable, BBR bounded), even if exact numbers differ slightly between machines.

*→ This is a natural point to draft the Design Report (topology diagram, timing diagrams, header table, amplification math) since M0–M3 give you everything it needs.*

---

## M4 — Defenses: Skip-Test + eBPF Detector

**Goal:** At least one working, demonstrable defense with before/after evidence; ideally both for the bonus.

**Tasks**
- [ ] Sherwood randomly-skipped-segment test built into the `server`'s send loop (Ch. 12) — no special container privileges needed
- [ ] eBPF/XDP (or `tc`-BPF, given the Docker networking caveat from §1) ACK-anomaly detector in the `server` container, `cap_add: [NET_ADMIN, SYS_ADMIN, BPF]` (or `privileged: true` if your Docker/kernel version requires it — document which)
- [ ] Detector logs anomalies and drops/RSTs the offending flow

**Verification gate:**
```bash
# Before:
docker compose run --rm attacker ./attack --target server --port 5000
# (cwnd inflates unchecked — same as M2)

# After (defense enabled):
DEFENSE=on docker compose up -d server
docker compose run --rm attacker ./attack --target server --port 5000
# PASS = server logs a detected "optimistic ACK" event, the connection is dropped/RST,
#        and a clean iperf3 run WITH the defense enabled stays within ~1-5% of the
#        M0 baseline throughput
```
**Definition of done:** a documented before/after pair (screenshots/logs) for at least one defense, plus a measured overhead number, with an explicit note in the report if that overhead number came from bare metal/Mininet rather than Docker (per the XDP caveat in §1).

---

## M5 — Reproducibility Package + Final Report/Demo

**Goal:** Anyone (a grader, a future employer) can clone the repo and reproduce every headline result with one command.

**Tasks**
- [ ] `README.md` at repo root: architecture diagram, exact `docker compose` commands for every milestone gate above, pinned image versions
- [ ] Fixed random seeds (attack timing jitter, skip-test schedule) so runs are exactly repeatable
- [ ] Final report + rehearsed live demo (attacker/server/observer screens, per Ch. 19 of the book)
- [ ] Member-contribution table

**Verification gate (the "cold clone" test — do this on a machine/VM neither of you has used for dev):**
```bash
git clone <repo> && cd <repo>
docker compose up -d
./scripts/run_all_gates.sh   # re-runs the M0–M4 gate checks above end-to-end
# PASS = every milestone's gate check above passes with zero manual intervention
```
**Definition of done:** the cold-clone test passes. If it doesn't, the project isn't actually reproducible yet — fix this before the demo, not during it.

---

## Testing Philosophy (applies to every milestone, not just the gates above)

- **Never move to milestone N+1 with milestone N's gate red.** A small number of milestones only works as a safety net if each gate is actually enforced.
- **Both teammates run every gate independently.** "It works in Docker on my machine" is not a passed gate on a 2-person Docker project — the whole point of Docker here is that it must work identically for both of you.
- **Keep a baseline (M0/M1) around forever.** Every later measurement (M2 attack inflation, M3 CC comparison, M4 defense overhead) is a ratio against that baseline — if the baseline drifts (different host, different Docker version), your numbers stop being comparable to each other.
- **Log raw data, not just plots.** `sweep_results.json`, `ss` CSV logs, and `tcpdump` captures should all be kept in the repo (or a linked artifact store) so a claim in the report can always be traced back to raw evidence.
