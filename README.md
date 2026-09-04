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

At M0, all three images were minimal and just proved the network + shaping + measurement
pipeline works end-to-end. As of M1, `server` runs a real custom TCP streaming server
(`server/stream_server.c`) with congestion control selectable via the `CC_ALGO`
environment variable, and `observer`/`attacker` can pull from it with `nc`.

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

## Milestone 1 — streaming server + congestion-control instrumentation

`server/stream_server.c` is a minimal memory-backed TCP streaming server. It reads
`CC_ALGO` from its environment once at startup and applies it to every accepted
connection via `setsockopt(TCP_CONGESTION)` — the per-socket approach required here,
since all three containers share one host kernel (see `PROJECT_IMPLEMENTATION_PLAN.md`,
§1).

### Running one CC algorithm

```bash
CC_ALGO=cubic docker compose up -d --force-recreate server
docker compose logs server   # confirms "listening on port 5000, CC_ALGO=cubic"
```

### Verification gate

```bash
./scripts/test_streaming.sh cubic 10
./scripts/test_streaming.sh reno  10
./scripts/test_streaming.sh bbr   10
```

Each run: (re)starts `server` with that `CC_ALGO`, shapes **`server`'s own egress**
(10 Mbit/20 ms/limit 50 — see the important note below on *why* it's the server and not
the client), has `observer` pull from it for N seconds via `nc`, prints a mid-stream
`ss -ti` snapshot, and appends `cc_algo,duration_s,bytes,mbit_s` to
`data/streaming_results.csv`.

**Pass criteria:**
- The `ss -ti` snapshot's first word after the socket line matches the requested
  algorithm (`cubic`/`reno`) and shows healthy congestion-avoidance numbers
  (`cwnd` near `ssthresh`, `send`/`delivery_rate` near the shaped 10 Mbit/s, no
  retransmit storm)
- The pull completes and reports throughput in roughly the 7–10 Mbit/s range
- Both teammates get consistent (±10%) results from a clean clone

**Actual measured results (this environment):**

| CC_ALGO | `ss -ti` confirms | Throughput | Notes |
|---|---|---|---|
| `cubic` | ✅ `cubic` | ~9.4 Mbit/s | cwnd/ssthresh stable, matches shaped link |
| `reno`  | ✅ `reno`  | ~9.4 Mbit/s | nearly identical to cubic — expected, no real loss on this link |
| `bbr`   | ❌ falls back to `cubic` | ~9.4 Mbit/s | `setsockopt(TCP_CONGESTION, "bbr")` fails: **BBR kernel module is not available on this host** |

### ⚠️ Known limitation: BBR is not available on every Docker host

Docker containers share the **host's** kernel — they cannot load their own kernel
modules. On a Docker Desktop VM (macOS/Windows) or a Linux host that never loaded
`tcp_bbr`, `net.ipv4.tcp_available_congestion_control` will list only `reno cubic`, and
`stream_server` will print:

```
[server] WARNING: could not set congestion control to 'bbr': No such file or directory
```

...then silently continue with the connection's existing default (cubic) — by design,
this is a graceful fallback, not a crash. Check what your host supports before relying
on BBR:

```bash
docker compose exec server sysctl net.ipv4.tcp_available_congestion_control
```

If `bbr` is missing, **M1's cubic/reno results still stand** (that's the actual gate).

**Confirmed on Docker Desktop (macOS, kernel `6.12.54-linuxkit`): `tcp_bbr.ko` does not
exist anywhere on that kernel** — this was verified directly (bind-mounted the VM's real
`/lib/modules` into a privileged container and ran `modprobe tcp_bbr` against it; result:
`FATAL: Module tcp_bbr not found`). This is not a "module not loaded" problem fixable
from inside Docker — the code was never compiled into that kernel build, and no
container-level trick can add kernel code that isn't there. If neither of you wants to
install/maintain a separate Linux VM, **don't** — use
[`.github/workflows/cc-comparison.yml`](.github/workflows/cc-comparison.yml) instead:
it runs the exact same `test_streaming.sh cubic/reno/bbr` gate on a GitHub-hosted
`ubuntu-latest` runner, which is a real Linux kernel with BBR available, spun up and
discarded per run — nobody has to own or configure a VM. Trigger it from the repo's
**Actions** tab (or it runs automatically on push to `main`); results land in the run's
**Artifacts** as `streaming-results/streaming_results.csv`.

### Two-teammate note: netem direction matters

Unlike the M0 baseline (attacker was the sender, so *attacker's* egress was shaped),
here **`server` is the bulk sender**, so `test_streaming.sh` shapes **`server`'s**
egress. `tc`/`netem` only ever shapes the egress of the interface it's attached to —
whichever container is sending the bulk data in a given test is the one that needs
shaping. Get this backwards (as the first draft of this script did) and you'll see
multi-hundred-Mbit/s throughput on what should be a 10 Mbit/s link, with no error to
tell you why.

## Tear down

```bash
docker compose down
```

## Next milestone

M2 — working optimistic-ACK attack against `cubic` (raw-socket C tool). See
`PROJECT_IMPLEMENTATION_PLAN.md`.
