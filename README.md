# Optimistic TCP ACK Attack — Project

Docker-based implementation of the optimistic TCP ACK attack, multi-congestion-control
comparison, and defenses (Sherwood skipped-segment test + eBPF/XDP detector).

Full background theory: see [`docs/Optimistic-TCP-ACK-Attacks.pdf`](docs/Optimistic-TCP-ACK-Attacks.pdf)
(project book) and [`PROJECT_IMPLEMENTATION_PLAN.md`](PROJECT_IMPLEMENTATION_PLAN.md)
(milestone plan).

## Requirements

- Docker Desktop / Docker Engine with Compose v2 (`docker compose version` should work)
- Linux host (or Docker Desktop on macOS/Windows) with the `tcp_bbr` kernel module
  available for later milestones (`sysctl net.ipv4.tcp_available_congestion_control`)

## Architecture (Milestone 0)

Three containers on a dedicated bridge network `labnet` (172.28.0.0/16):

| Service    | IP           | Role                                      | Capabilities        |
|------------|--------------|--------------------------------------------|----------------------|
| `server`   | 172.28.0.10  | Victim / streaming server (later)          | `NET_ADMIN`          |
| `attacker` | 172.28.0.20  | Misbehaving receiver / attack tool (later) | `NET_RAW`, `NET_ADMIN` |
| `observer` | 172.28.0.30  | Honest client / dashboard (later)          | `NET_ADMIN`          |

At M0, all three images are minimal (`iproute2`, `tcpdump`, `iperf3`, `python3`) and just
prove the network + shaping + measurement pipeline works end-to-end. They will gain
real application code in later milestones.

## Milestone 0 — bring the testbed up

```bash
docker compose build
docker compose up -d
docker compose ps
```

Sanity-check connectivity:

```bash
docker compose exec attacker ping -c 3 server
```

## Milestone 0 — verification gate

1. Shape the attacker→server link (10 Mbit/s, 20 ms delay, 50-packet queue):

   ```bash
   ./scripts/apply_netem.sh attacker 10 20 50
   ```

2. Run the baseline throughput test:

   ```bash
   ./scripts/run_baseline.sh
   ```

**Pass criteria:**
- `apply_netem.sh` prints a `netem` line (not `noqueue`/`pfifo_fast`) when it shows
  `tc qdisc show dev eth0`
- `run_baseline.sh` reports throughput reasonably close to the configured 10 Mbit/s
  (some overhead from TCP/IP framing and the 20ms RTT ramp-up is expected — anything
  roughly in the 7–10 Mbit/s range with zero or near-zero retransmits is a pass)
- Both teammates get consistent (±10%) results running the exact same two commands
  from a clean `git clone`

Raw results land in `data/baseline.json` (git-ignored — regenerate it, don't commit it).

## Tear down

```bash
docker compose down
```

## Next milestone

M1 — streaming server with selectable congestion control + `ss -ti` instrumentation.
See `PROJECT_IMPLEMENTATION_PLAN.md`.
