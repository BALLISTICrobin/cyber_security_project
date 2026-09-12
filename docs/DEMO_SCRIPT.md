# Live Demo Script

Target length: ~8-10 minutes. Run through this once, fully, before the real demo —
timings below assume a warm Docker build (images already built).

Terminal layout: 3 terminals side by side if possible — labeled **SERVER**, **ATTACKER**,
**OBSERVER** — so the audience can see all three roles at once. If only one screen is
available, run them sequentially and narrate what would be happening on the others.

## 0. Setup (before the audience is watching)

```bash
docker compose build
docker compose up -d
docker compose exec attacker ping -c 2 server   # sanity check, should show 0% loss
```

## 1. "Here's the honest baseline" (~1 min)

**SERVER:**
```bash
CC_ALGO=cubic docker compose up -d --force-recreate server
docker compose logs -f server
```
*(leave this running — narrate: "the server is a custom TCP streamer, congestion
control picked per-connection")*

**OBSERVER:**
```bash
./scripts/apply_netem.sh server 10 20 50    # shape the server's egress
timeout 10 nc server 5000 | wc -c
```
*Say: "~1.25 MB/s, matches our 10 Mbit shaped link, this is what honest TCP looks like."*

## 2. "Now watch the attack" (~3 min) — the core moment

**SERVER:**
```bash
watch -n 0.3 'docker compose exec server ss -ti dst attacker'
```
*(this is the money shot — point at `cwnd` and `rtt` before starting the attack)*

**ATTACKER:**
```bash
docker compose exec attacker /work/attack --target server --port 5000 \
  --duration 20 --sack --timestamps -v
```

*Narrate live as the SERVER window updates:*
- "`cwnd` is climbing into the thousands — it should plateau around a few dozen"
- "`rtt` is collapsing toward zero — the attacker is telling the server every ACK
  arrives instantly"
- "the server has no way to know any of this is a lie — it's behaving exactly as
  designed, on false information"

## 3. "Quantified" (~1 min)

```bash
CC_ALGO=cubic ./scripts/run_attack.sh 15 20 2
```
*Point at the final inflation factor line — expect double digits to low hundreds ×.*

## 4. "It's worse on some algorithms than others" (~1 min)

Show the pre-generated figure (don't regenerate live, it takes minutes):
```bash
open data/fig_amplification.png     # or: xdg-open on Linux
```
*Say: "SACK is the deciding factor — without it, the attack can actually
self-destruct against NewReno's duplicate-ACK logic. With it, both Reno and CUBIC
blow up 100×+. BBR (shown in our CI results, not reproducible on this laptop's
kernel) is bounded instead of unbounded — it paces from a bandwidth model instead of
trusting every ACK."*

## 5. "Here's the fix" (~2 min)

**SERVER:**
```bash
DEFENSE=on docker compose up -d --force-recreate server
docker compose logs -f server
```

**ATTACKER (same attack, unchanged):**
```bash
docker compose exec attacker /work/attack --target server --port 5000 \
  --duration 10 --sack
```
*Point at the SERVER log: `OPTIMISTIC ACK DETECTED ... resetting flow`.*

**OBSERVER (prove honest clients are unaffected):**
```bash
timeout 8 nc server 5000 | wc -c
```
*Say: "~1.8 MB transferred, zero detections — the defense doesn't punish honest
clients, only ones that provably lied."*

## 6. "And it's all reproducible" (~1 min, closing)

```bash
./scripts/run_all_gates.sh
```
*Let it run in the background while you talk over the closing summary; don't wait for
it live (~3-4 min total) — cut to the pre-recorded summary output if time is short:*
```
ALL GATES PASSED
```

## Fallback plan if something breaks live

- **Attack doesn't inflate cwnd:** check `docker compose exec attacker /work/attack --help`
  ran with `--sack` — without it, amplification is unreliable by design (see §4 of
  `FINAL_REPORT.md`). Also confirm the server was actually recreated with `CC_ALGO=cubic`
  (`docker compose logs server | tail -1`).
- **BBR row asked about:** don't try to demo it live — say explicitly "our Docker
  Desktop kernels don't ship BBR; the real numbers are in our CI runs," and show a
  screenshot of the GitHub Actions artifact instead. This is a documented, understood
  limitation, not something to awkwardly work around live.
- **Full reset:** `docker compose down && docker compose up -d`, re-run from §1.
