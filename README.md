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

## Architecture

Four containers, defined in one `docker-compose.yml`:

| Service     | IP           | Network  | Role                                | Capabilities           |
|-------------|--------------|----------|--------------------------------------|------------------------|
| `server`    | 172.28.0.10  | `labnet` | Victim / streaming server            | `NET_ADMIN`, `NET_RAW`  |
| `attacker`  | 172.28.0.20  | `labnet` | Misbehaving receiver / attack tool   | `NET_RAW`, `NET_ADMIN`  |
| `observer`  | 172.28.0.30  | `labnet` | Honest client                        | `NET_ADMIN`             |
| `dashboard` | (host only, port `8787`) | default | Web control panel (optional) | none — controls the other three via the Docker socket, not the network |

`server` runs a real custom TCP streaming server (`server/stream_server.c`, or
`server/defense_server.c` when `DEFENSE=on`) with congestion control selectable via the
`CC_ALGO` environment variable; `observer`/`attacker` can pull from it with `nc`.
`dashboard` is a thin control-panel UI over the same commands documented below — see
[Web dashboard](#web-dashboard) further down for what it adds and, importantly, its own
security note (mounting the Docker socket is root-equivalent host access).

## Bring everything up (one command)

```bash
docker compose up -d --build
docker compose ps      # expect: attacker, server, observer, dashboard, all "Up"
```

This builds and starts **all four containers at once**, including the dashboard —
open [http://localhost:8787](http://localhost:8787) once it's up. `--build` is only
needed the first time or after changing a `Dockerfile`/`.c` file; plain `docker compose
up -d` is enough otherwise.

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
docker compose exec attacker /work/attack --target server --port 5000 --duration 15 --sack --timestamps
docker compose exec attacker /work/attack --target server --port 5000 --lazy   # fallback variant
docker compose exec server ss -tin dst attacker      # watch cwnd/rtt during the run
```

The gate negotiates SACK and TCP timestamps (`--sack --timestamps`), exactly as
a real modern TCP receiver does. This also makes the attack robust: the M3 sweep
(see below) shows that without SACK the overrun-recovery ACKs look like
duplicates to NewReno and the window collapses, whereas with it the server keeps
the window wide open (≈160× amplification on CUBIC versus ≈0.5× without).

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

**Actual measured result (CI, `ubuntu-latest`, CUBIC, 20 ms / 2% loss, from the
M3 sweep):**

| Metric | Honest | Under attack (SACK) |
|---|---|---|
| Server egress | 5.88 Mbit/s | 963 Mbit/s |
| Peak cwnd | 20 | 6111 |
| Amplification | — | **≈164×** (gate ≥ 3×) → **PASS** |

The `ss -ti` snapshot mid-attack shows the signature exactly: the congestion
window is held in the thousands of segments while `ssthresh` records that CUBIC
*wanted* to collapse the window after loss — the optimistic ACKs simply never
let it.

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

## Milestone 4 — defense: Sherwood randomly-skipped-segment test

`server/defense_server.c` is a streaming server that catches a lying receiver
directly. Every so often it **skips** a segment — it advances its send sequence
past a small gap without transmitting those bytes — and remembers the hole:

- an **honest** receiver never got the skipped bytes, so its cumulative ACK
  cannot advance past the hole; it stalls there until the server retransmits
  (which it does after a short grace period, so honest clients are never harmed);
- a **misbehaving optimistic** receiver acknowledges data it never received, so
  it ACKs straight past the hole — impossible for an honest peer. The server
  logs it and RSTs the flow.

Because it has to control its own TCP sequence numbers to leave a hole (a normal
kernel socket cannot), it is a raw-socket server, selected with `DEFENSE=on`
(needs `NET_ADMIN` + `NET_RAW` + iptables, all in `docker-compose.yml`). Unlike
M2/M3 it needs no `netem` or `tcp_bbr`, so the whole gate runs on Docker Desktop.

### Running it

```bash
DEFENSE=on docker compose up -d --force-recreate server   # skip-test server
docker compose exec attacker /work/attack --target server --port 5000 --sack   # detected + reset
docker compose exec observer sh -c "nc server 5000 | wc -c"                      # honest: fine
```

### Verification gate

```bash
./scripts/run_defense.sh 8
```

This runs three phases — attacker with the defense off (unchecked baseline),
attacker with it on (detected and reset), and an honest client with it on
(completes, not flagged).

**Pass criteria (M4 definition of done):** the attack is detected and reset, the
attacker's throughput collapses versus the unchecked baseline, and the honest
client transfers normally without being flagged.

**Actual measured result (this project's Docker Desktop host):**

| Phase | Result |
|---|---|
| Attacker, defense off | ≈1083 Mbit/s (streams freely) |
| Attacker, defense on | ≈2.5 Mbit/s — **detected on a skipped segment, flow reset** |
| Honest client, defense on | ≈14.7 MB transferred, **0 detections** |

[`.github/workflows/m4-defense.yml`](.github/workflows/m4-defense.yml) runs the
same gate on `ubuntu-latest`.

### Note on the eBPF/XDP detector (bonus)

The plan also lists an eBPF/XDP ACK-anomaly detector for the bonus. Note that the
realistic attack here acknowledges data the server *did* send but that was
dropped downstream, so a naive "ACK beyond snd_nxt" check does not catch it (the
kernel already rejects those) — the deliberate skip-test above is what exposes
the lie. An in-kernel version of the same skip-and-detect logic (tc-BPF on the
server, whose `clsact` hook is available here) is the natural bonus extension;
its overhead number must be measured on bare metal, since eBPF runs in generic
mode inside Docker (see `PROJECT_IMPLEMENTATION_PLAN.md`, §1).

## Milestone 5 — reproducibility package, final report, demo

`scripts/run_all_gates.sh` is the project's "cold clone" test: it rebuilds every image,
brings up the testbed, and re-runs every milestone's gate (M0-M4) in sequence, ending in
one PASS/FAIL/SKIP summary. This is what "the project is reproducible" actually means —
not that it worked once on someone's laptop.

```bash
./scripts/run_all_gates.sh
```

`SKIP` (not `PASS` or `FAIL`) is expected for the `bbr` rows on any host without the
`tcp_bbr` kernel module (see the M1/M3 sections above) — that's a documented host
limitation, resolved via CI, not a project bug.

### Fixed seeds

Both raw-socket tools accept a seed for exact repeatability (source port + initial
sequence number), on top of their default time/pid-derived randomness:

```bash
docker compose exec attacker /work/attack --target server --port 5000 --seed 42
DEFENSE_SEED=42 DEFENSE=on docker compose up -d --force-recreate server
```

### Final report and demo

- [`docs/FINAL_REPORT.md`](docs/FINAL_REPORT.md) — consolidated results across all
  milestones, with the actual measured numbers and their significance.
- [`docs/DEMO_SCRIPT.md`](docs/DEMO_SCRIPT.md) — the rehearsed live-demo walkthrough
  (honest baseline → attack → quantified inflation → multi-CC figure → defense →
  reproducibility), with a fallback plan if something breaks live.

### Contributions

| Area | Contributor |
|---|---|
| M0 — Dockerized testbed, netem shaping, baseline gate | BALLISTICrobin |
| M1 — streaming server, per-socket CC selection, BBR host-limitation diagnosis + CI | BALLISTICrobin |
| M2 — raw-socket attack tool, Scapy prototype, attack gate + CI | sayjad |
| M3 — CC x timestamps x SACK sweep, dashboard figures, sweep CI | sayjad |
| M4 — Sherwood skip-test defense server, defense gate + CI | sayjad |
| M5 — `run_all_gates.sh`, seed reproducibility, final report, demo script | BALLISTICrobin |
| Cross-cutting — independent verification of every milestone's gate on a second machine, bug fixes (executable bits, M0/M1 pass/fail criteria) | BALLISTICrobin |

## Web dashboard

`dashboard/server.py` is a control-panel UI over this exact project — same
`docker compose exec ...` commands documented throughout this README, just with buttons
and live charts instead of a terminal and raw `ss -ti` text. Zero third-party Python
dependencies (stdlib only).

**It's part of `docker compose up -d`** (see [above](#bring-everything-up-one-command))
— no separate command needed:

```bash
docker compose up -d --build
# open http://localhost:8787
```

### How this actually runs: Docker controlling Docker

The `dashboard` container doesn't join `labnet` and never talks to `server`/`attacker`/
`observer` over the network — it drives them by running `docker compose ...` against the
**same Docker daemon your host uses**, via two things mounted into it
(see `docker-compose.yml` and `docker/dashboard/Dockerfile`):

1. `/var/run/docker.sock` — the Docker socket, so the `docker` CLI inside the container
   talks to your real daemon, not a nested one.
2. The live project directory, bind-mounted at the **same absolute path** inside the
   container as on your host (the `${PWD}:${PWD}` trick) — required so that when the
   dashboard's `docker compose` invocation resolves the compose file and volume paths,
   they're paths the daemon can actually see.

**⚠️ Security note:** mounting the Docker socket into a container gives that container
root-equivalent control over your host's Docker (and, effectively, your host) — this is
a well-known, standard pattern (the same one CI runners like Jenkins/GitLab use to build
Docker images from inside a job), fine for a personal lab tool you run yourself, but it
is **not something to expose beyond `localhost`**. Don't publish port 8787 to a network
or the internet, and don't add this pattern to anything multi-tenant.

Two of the dashboard's own buttons are scoped specifically because of this setup: "Bring
testbed up" and "Tear down" explicitly target `server attacker observer` by name (never
a bare `docker compose up -d` / `down`) so that clicking them can't recreate or remove
the dashboard's own container out from under the page you're looking at — verified
directly: tearing down via the UI leaves `dashboard` running and reachable, and bringing
the testbed back up via the UI restores the other three without touching it.

### Guided scenario (start here)

The main page walks through the whole project as six fixed steps — Setup, Honest
baseline, Attack with SACK, Attack without SACK, Enable the defense, Summary — each with
a "Run this step" button. Every step drives the real backend (the same endpoints the
manual controls below use), then auto-computes that step's measured results (peak cwnd,
min RTT, mean throughput, amplification vs. the honest baseline, and any
`OPTIMISTIC ACK DETECTED` count) into a running **session report table** — a
self-generating summary of the whole demo, not something you have to read off charts by
eye.

Above the scenario, a live **network topology view** (Attacker / Server / Observer)
animates packets flowing between nodes: an upper lane for the bulk data stream and a
lower lane for ACKs, with dot speed/density driven by the real, currently-polled
throughput and RTT — denser and faster under the real attack, a modest, realistically-paced
trickle for the honest connection. This is an **illustrative** animation (it is not a
literal packet-capture replay — there's no per-packet telemetry to replay), but every
input driving it is a real live measurement, not a canned/scripted sequence.

The detailed metric cards, raw charts, and manual buttons (CC algorithm, shaping,
one-off attack/honest runs) are still available under "Show advanced / manual controls"
for direct exploration outside the fixed scenario.

**Note on the defense step's report row:** `server/defense_server.c` drives its
connection entirely from a raw socket (it has to, to leave deliberate sequence-number
gaps a normal kernel socket can't), so it has no kernel TCB and **never appears in
`ss -ti` at all**. The defense step's report row therefore correctly shows "—" for the
ss-derived columns (peak cwnd, RTT, throughput) — that's accurate information ("we can't
observe this via ss"), not missing data — while still correctly counting real
`OPTIMISTIC ACK DETECTED` events, which come from the server's log output instead.

This is a convenience layer for exploring the project interactively (e.g. in class, or
for your own understanding) — it is **not** a replacement for the scripted gates above,
which are what actually prove the project works. Same scope note as everywhere else in
this repo: only point it at your own isolated `labnet` testbed.

## Manual Testing Guide

Two ways to convince yourself (or a grader) this actually works: driving it by hand from
a terminal (below), or clicking through the dashboard UI (further down). Both exercise
the *exact same* underlying tools — pick whichever matches how you want to demo it.

### A. Manual testing from the command line

**1. Bring the testbed up and confirm connectivity**

```bash
docker compose up -d --build
docker compose exec attacker ping -c 3 server        # expect 0% packet loss
docker compose logs server                            # "listening on port 5000, CC_ALGO=cubic"
```

**2. Shape the link and check the honest baseline**

Use loss+delay, not a rate cap — a rate cap on the server's own egress creates local
back-pressure that hides the attack's effect (see Milestone 2 above for why):

```bash
docker compose exec server tc qdisc replace dev eth0 root netem delay 20ms loss 2%
docker compose exec server tc qdisc show dev eth0     # confirm it says "netem ... delay 20ms loss 2%"

docker compose exec -d observer sh -c "timeout 8 nc server 5000 > /dev/null"
sleep 2
docker compose exec server ss -ti dst observer
```

Expect a small `cwnd` (single/low-double digits), `rtt`/`minrtt` around 20ms, and some
real `retrans` (~2% of segments) — CUBIC honestly respecting real loss on the link.

**3. Launch the attack and compare**

```bash
docker compose exec -d attacker /work/attack --target server --port 5000 \
  --duration 10 --sack --timestamps -v
sleep 4
docker compose exec server ss -ti dst attacker
```

Expect `cwnd` in the thousands (vs. the honest run's low double digits), `minrtt`
collapsed to under 1ms despite the link still genuinely having a 20ms floor, and
`retrans` barely moving even though the real 2% loss is still happening underneath —
the server just never finds out, because the attacker's ACKs cover for it. For the
quantified version of this same comparison:

```bash
CC_ALGO=cubic ./scripts/run_attack.sh 15 20 2
```

**4. Prove it's SACK-dependent, not just "the attack works"**

```bash
docker compose exec -d attacker /work/attack --target server --port 5000 \
  --duration 10 --timestamps -v        # note: no --sack this time
sleep 4
docker compose exec server ss -ti dst attacker
```

Expect `cwnd` to stay *small* — often smaller than the honest baseline — because without
SACK, the attacker's overrun-recovery ACKs look like ordinary duplicate ACKs to CUBIC and
can shrink the window instead of growing it. Seeing both outcomes from the same tool is
much stronger evidence than either one alone.

**5. Test the defense**

```bash
DEFENSE=on docker compose up -d --force-recreate server
docker compose logs -f server &                       # watch for the detection line
docker compose exec attacker /work/attack --target server --port 5000 --duration 8 --sack
```

Expect a log line within a couple of seconds:
`[defense] OPTIMISTIC ACK DETECTED: client acked ..., past skipped segment [...) it never received -- resetting flow`,
and the attacker's throughput collapsing to near-nothing. Then confirm honest clients are
unaffected:

```bash
docker compose exec observer sh -c "nc server 5000 | wc -c"   # should transfer real bytes, and NOT be flagged
```

Or run all three phases (unchecked / defended / honest) at once with the scripted gate:

```bash
./scripts/run_defense.sh 8
```

**6. Clean up**

```bash
docker compose exec server tc qdisc del dev eth0 root
docker compose down
```

**Or run every gate above, end to end, in one shot:**

```bash
./scripts/run_all_gates.sh
```

### B. Manual testing via the dashboard UI

```bash
docker compose up -d --build
# open http://localhost:8787
```

**Guided scenario (recommended first pass):** click **"Run this step"** six times in a
row — Setup → Honest baseline → Attack with SACK → Attack without SACK → Enable the
defense → Summary. Watch the **Network view** animate (denser/faster packets during the
attack, a modest realistic trickle for the honest run) and the **Session report** table
fill in automatically after each step with the real measured numbers (peak cwnd, min
RTT, mean Mbit/s, amplification vs. baseline, and any detection count) — by the end you
have the full attack/defense story in one table, generated from live data, not typed in.

**Advanced / manual controls (for poking at it directly):** click **"Show advanced /
manual controls"** at the bottom of the page to reveal the same controls the guided
scenario automates, usable independently and in any order:

| Control | What it does | Equivalent CLI command |
|---|---|---|
| Testbed: **Bring testbed up** / **Tear down** | Starts/stops `server`, `attacker`, `observer` (never the dashboard itself) | `docker compose up -d server attacker observer` / `docker compose rm -f -s server attacker observer` |
| Server: CC dropdown + defense checkbox + **Apply** | Recreates `server` with the chosen `CC_ALGO` and `DEFENSE` | `CC_ALGO=<algo> DEFENSE=<on\|off> docker compose up -d --force-recreate server` |
| Link shaping: delay/loss + **Apply shaping** / **Clear** | Shapes or clears `server`'s egress | `docker compose exec server tc qdisc replace dev eth0 root netem delay <N>ms loss <N>%` |
| Honest baseline: duration + **Run honest pull** | `observer` pulls from `server` for N seconds | `docker compose exec -d observer sh -c "timeout <N> nc server 5000 > /dev/null"` |
| Attack: SACK/timestamps/lazy + duration + seed + **Launch attack** | Runs the attack tool with the chosen flags | `docker compose exec -d attacker /work/attack --target server --port 5000 --duration <N> [--sack] [--timestamps] [--lazy] [--seed <N>]` |

While any of these run, the **Live numbers** cards, the three **Charts**, and the
**Server log** panel (highlighting `OPTIMISTIC ACK DETECTED` / `flow reset` in red) all
update in real time from the same `ss -ti` polling and log tailing the guided scenario
uses — so you can, for example, click "Apply shaping", then "Launch attack" with SACK
off, then immediately re-launch with SACK on, and watch the charts show the difference
live without following the fixed 6-step order.

## Tear down

```bash
docker compose down
```

## Project status: complete

All five milestones (M0-M5) from `PROJECT_IMPLEMENTATION_PLAN.md` are implemented and
independently verified. See `docs/FINAL_REPORT.md` for results.
