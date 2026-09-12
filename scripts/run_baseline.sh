#!/usr/bin/env bash
# M0 verification gate: baseline throughput test, attacker -> server, over the
# shaped labnet link. Run this after apply_netem.sh.
set -euo pipefail

mkdir -p data

echo "[*] (Re)starting iperf3 server on 'server'..."
docker compose exec server pkill -f "iperf3 -s" 2>/dev/null || true
sleep 1
docker compose exec -d server iperf3 -s
sleep 1

echo "[*] Running 15s baseline test: attacker -> server"
docker compose exec attacker iperf3 -c server -t 15 -J > data/baseline.json

echo "[*] Result:"
RC=0
python3 - <<'PY' || RC=$?
import json, sys
with open("data/baseline.json") as f:
    d = json.load(f)
s = d["end"]["sum_received"]
sent = d["end"]["sum_sent"]
mbit = s["bits_per_second"] / 1e6
retrans = sent.get("retransmits", 0) or 0
print(f"    Throughput   : {mbit:.2f} Mbit/s over {s['seconds']:.1f}s")
print(f"    Retransmits  : {retrans}")
# Pass range assumes the standard 10mbit/20ms/limit50 shape from apply_netem.sh;
# TCP/IP framing overhead means we won't hit exactly 10, and an unshaped link
# (apply_netem.sh not run) would blow well past the upper bound too.
ok = 5.0 <= mbit <= 11.0 and retrans < 50
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY

echo "[*] Raw JSON saved to data/baseline.json"
exit $RC
