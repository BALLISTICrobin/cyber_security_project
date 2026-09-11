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

## Milestone 2 — optimistic-ACK attack (CUBIC)

`attacker/optack.c` is a raw-socket optimistic-ACK attack tool (compiled to
`/work/attack` in the attacker image). It is a misbehaving TCP *receiver*: it
opens a connection to the server and then acknowledges data before — or without
ever — receiving it, so the server's CUBIC congestion control sees a
near-zero-RTT, loss-free path, inflates its window without bound, and pours far
more traffic onto the wire than the path can carry (Savage 1999 / Sherwood 2005).

Design highlights (see `PROJECT_IMPLEMENTATION_PLAN.md`, §1 and §M2):

- **The whole connection, including the handshake, is driven from the raw
  socket.** The host kernel never has a TCB for the 4-tuple, so there is no
  kernel-vs-tool conflict. Because the kernel would otherwise RST the server's
  SYN-ACK (no socket owns the source port), the tool installs an `iptables`
  rule that drops outbound RSTs to the server for the run and removes it on exit
  (needs `NET_ADMIN`; raw send needs `NET_RAW` — both are in `docker-compose.yml`).
- **Optimism is self-tuning (AIMD), not a fixed prediction.** The tool tracks
  how far ahead of genuinely-received data it can acknowledge: it grows that
  lead while the server keeps sending, and halves it the moment the flow stalls
  (its ACKs overran the server's send pointer). This is Sherwood's opportunistic
  ACK with overrun recovery, and it cannot dead-lock — a fixed-rate predictor can.
- `attacker/optack_proto.py` is the Scapy prototype (M2 stage 1) that validates
  the packet format and handshake before the fast C tool.

### Running it

```bash
docker compose exec attacker /work/attack --target server --port 5000 --duration 15
docker compose exec attacker /work/attack --target server --port 5000 --lazy   # fallback variant
docker compose exec server ss -tin dst attacker      # watch cwnd/rtt during the run
```

### Verification gate

```bash
CC_ALGO=cubic ./scripts/run_attack.sh 15 20 2        # duration_s delay_ms loss_pct
```

This shapes the server's egress into a **lossy, delayed path** (netem
`delay 20ms loss 2%`, no rate cap), measures the server's egress under an honest
kernel-TCP client, then under the attack, and reports the inflation factor.

**Why loss + delay and not a rate cap:** the attack only matters where honest
CUBIC would back off but the attacker does not. A `rate` cap on the server's
*own* egress instead creates local back-pressure that stalls the server's send
pointer and hides the effect, so it is deliberately not used here (this is a
different measurement from the M0/M1 baseline, which intentionally used a rate
cap to model link capacity).

**Pass criteria (M2 definition of done):**
- `ss -ti` on the server shows the congestion window climbing far past its
  normal ceiling and the RTT collapsing toward zero during the attack.
- The server's egress under attack is **≥ 3× the honest baseline** over the same
  shaped path. Result is appended to `data/attack_results.csv`.

**Actual measured result (CI, `ubuntu-latest`, CUBIC, 20 ms / 2% loss):**

| Metric | Honest | Under attack |
|---|---|---|
| Server egress | 6.17 Mbit/s | 113.48 Mbit/s |
| Amplification | — | **18.39×** (gate ≥ 3×) → **PASS** |

The `ss -ti` snapshot mid-attack shows the signature exactly: `cwnd:177` held
wide open while `ssthresh:2` records that CUBIC *wanted* to collapse the window
after loss — the optimistic ACKs simply never let it.

### ⚠️ Same kernel limitation as BBR: no `netem` on Docker Desktop

Traffic shaping is what makes the gate meaningful, and Docker Desktop's LinuxKit
kernel ships **no `netem` (or `tbf`/`ifb`) qdisc and no loadable modules at
all** — confirmed on this project's dev machine. On such a host,
`run_attack.sh` detects the missing qdisc and runs a **correctness-only** pass:
the tool is exercised end-to-end (handshake, accepted optimistic ACKs, an
inflated `cwnd` visible in `ss -ti`, clean teardown), but the honest-vs-attack
ratio is not a pass/fail gate there — with no bottleneck to hide, optimism has
nothing to gain and the ratio is meaningless.

The real inflation number comes from CI, exactly like the BBR number:
[`.github/workflows/optack-attack.yml`](.github/workflows/optack-attack.yml)
runs the same `run_attack.sh` gate on a GitHub-hosted `ubuntu-latest` runner
(a real kernel with `netem`), spun up and discarded per run. Trigger it from the
**Actions** tab (or it runs on push to `main`); the inflation number lands in
the run's **Artifacts** as `attack-results/attack_results.csv`.

## Milestone 3 — CC × timestamps × SACK sweep + dashboard

`scripts/sweep.py` runs the attack across the full matrix of congestion-control
algorithm (Reno / CUBIC / BBR) × TCP timestamps (on/off) × SACK (on/off). For
each algorithm it first measures an honest kernel-TCP baseline over the same
shaped path, then runs the attack once per (timestamps, SACK) setting and records
the egress amplification and peak congestion window to `data/sweep_results.json`.

The attacker now supports the extra dimensions: `--timestamps` negotiates TCP
timestamps and echoes the server's `TSval` correctly (so PAWS does not drop the
forged ACKs), and `--sack` offers SACK-permitted. `--log FILE` writes a periodic
`delivered,acknowledged` time-series — the raw material for the "optimistic gap"
figure.

`scripts/plot_sweep.py` turns the results into three black-and-white figures
(`data/fig_amplification.png`, `data/fig_peak_cwnd.png`, `data/fig_gap.png`):
amplification by algorithm, peak congestion window (attack vs honest), and
acknowledged-vs-genuinely-delivered bytes over time. These double as the report's
dashboard figures.

### Running it

```bash
SWEEP_DURATION=10 python3 scripts/sweep.py       # writes data/sweep_results.json
python3 scripts/plot_sweep.py                    # needs matplotlib; writes data/*.png
```

### Verification gate

- `data/sweep_results.json` has one row per (cc, timestamps, sack) combination.
- CUBIC and Reno show large amplification (their windows trust ACKs and inflate
  without bound); **BBR stays bounded** — it paces from a bandwidth/RTT model, so
  faked ACKs buy far less, consistent with the aBBRate finding.

### Same kernel note as M2

The sweep needs `netem` **and** the `tcp_bbr` module, so — like the M2 gate and
the BBR comparison — the real numbers come from CI, not Docker Desktop.
[`.github/workflows/m3-sweep.yml`](.github/workflows/m3-sweep.yml) runs the sweep
on `ubuntu-latest` and uploads `sweep_results.json` and the three figures as the
`m3-sweep` artifact. Run locally without `netem` and `sweep.py` reports a
correctness-only pass (the matrix executes but the ratios are not meaningful).

## Tear down

```bash
docker compose down
```

## Next milestone

M4 — defenses: Sherwood randomly-skipped-segment test + an eBPF/XDP ACK-anomaly
detector, with before/after evidence. See `PROJECT_IMPLEMENTATION_PLAN.md`.
