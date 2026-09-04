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
python3 - <<'PY'
import json
with open("data/baseline.json") as f:
    d = json.load(f)
s = d["end"]["sum_received"]
sent = d["end"]["sum_sent"]
print(f"    Throughput   : {s['bits_per_second']/1e6:.2f} Mbit/s over {s['seconds']:.1f}s")
print(f"    Retransmits  : {sent.get('retransmits', 'n/a')}")
PY

echo "[*] Raw JSON saved to data/baseline.json"
