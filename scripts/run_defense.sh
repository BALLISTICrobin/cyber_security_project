#!/usr/bin/env bash
# Milestone 4 verification gate: show that the Sherwood randomly-skipped-segment
# defense detects and stops the optimistic-ACK attacker, while leaving an honest
# client unharmed.
#
# Three phases, all runnable on any Docker host (no netem/eBPF needed):
#   1. defense OFF  -> attacker streams freely (baseline "unchecked" throughput)
#   2. defense ON   -> attacker is detected on a skipped segment and RST; it gets
#                      almost nothing
#   3. defense ON   -> an honest kernel-TCP client completes normally and is NOT
#                      flagged
#
# Usage: ./scripts/run_defense.sh [duration_s]
set -euo pipefail
export MSYS_NO_PATHCONV=1
DUR="${1:-8}"
dc() { docker compose "$@"; }

mbit_of() { grep -oE '[0-9]+\.[0-9]+ Mbit/s' | head -1 | grep -oE '[0-9]+\.[0-9]+'; }

echo "[*] Phase 1: defense OFF -- attacker streams unchecked"
DEFENSE=off dc up -d --force-recreate server >/dev/null; sleep 1
BEFORE=$(dc exec -T attacker /work/attack --target server --port 5000 \
           --duration "${DUR}" --sack 2>&1 | mbit_of || echo 0)
echo "    attacker received: ${BEFORE:-0} Mbit/s"

echo "[*] Phase 2: defense ON -- attacker should be detected + reset"
DEFENSE=on dc up -d --force-recreate server >/dev/null; sleep 1
AFTER=$(dc exec -T attacker /work/attack --target server --port 5000 \
          --duration "${DUR}" --sack 2>&1 | mbit_of || echo 0)
sleep 1
DET=$(dc logs --since "$((DUR + 5))s" server 2>&1 | grep -c "OPTIMISTIC ACK DETECTED" || true)
echo "    attacker received: ${AFTER:-0} Mbit/s"
echo "    server detections logged: ${DET}"
dc logs --since "$((DUR + 5))s" server 2>&1 | grep -E "DETECTED|reset" | sed 's/^/      /' | head -2 || true

echo "[*] Phase 3: defense ON -- honest client should complete, NOT be flagged"
dc exec -T server sh -c "true"  # ensure server still up
HON_BYTES=$(dc exec -T observer sh -c "timeout ${DUR} nc server 5000 | wc -c" 2>/dev/null | tr -d '[:space:]')
sleep 1
HON_DET=$(dc logs --since "$((DUR + 3))s" server 2>&1 | grep -c "OPTIMISTIC ACK DETECTED" || true)
echo "    honest client received: ${HON_BYTES:-0} bytes; flagged: ${HON_DET}"

echo
echo "=============================================================="
echo " attacker throughput  unchecked : ${BEFORE:-0} Mbit/s"
echo " attacker throughput  defended  : ${AFTER:-0} Mbit/s"
echo " attack detected by skip-test   : ${DET} time(s)"
echo " honest client bytes (defended) : ${HON_BYTES:-0}"
echo "=============================================================="

# PASS = attack detected, honest client moved real data and was not flagged.
python3 - "$DET" "${HON_BYTES:-0}" "$HON_DET" <<'PY'
import sys
det, hon_bytes, hon_det = int(sys.argv[1]), int(sys.argv[2] or 0), int(sys.argv[3])
ok = det >= 1 and hon_bytes > 100000 and hon_det == 0
print("RESULT:", "PASS" if ok else "FAIL")
sys.exit(0 if ok else 1)
PY
