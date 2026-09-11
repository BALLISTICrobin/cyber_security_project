#!/usr/bin/env bash
# Milestone 2 verification gate: measure the egress inflation caused by the
# optimistic-ACK attack against our own CUBIC server, versus an honest
# kernel-TCP baseline over the same shaped path.
#
# The "link" is modelled as a lossy, delayed path (netem delay + loss, no hard
# rate cap). That is the setup where the attack matters: honest CUBIC treats the
# loss as congestion and backs off, while an optimistic receiver hides the loss
# and keeps the server's window wide open, so the server pours far more bytes
# onto the wire than the path can carry -- the denial-of-service / congestion-
# collapse effect. A rate cap on the server's *own* egress is deliberately NOT
# used: it would create local back-pressure that stalls the server's send
# pointer and hides the very effect we are measuring.
#
# Metric: server IpExt OutOctets (bytes handed to IP, i.e. injected onto the
# wire, retransmits included), sampled before/after each run.
#
# Usage: ./scripts/run_attack.sh [duration_s] [delay_ms] [loss_pct]
# Example: ./scripts/run_attack.sh 15 20 2
set -euo pipefail
export MSYS_NO_PATHCONV=1        # keep Git Bash from mangling /work/... paths

CC_ALGO="${CC_ALGO:-cubic}"
DURATION="${1:-15}"
DELAY="${2:-20}"
LOSS="${3:-2}"
MIN_INFLATION="${MIN_INFLATION:-3.0}"
mkdir -p data

dc() { docker compose "$@"; }

# Server bytes injected onto the wire (IpExt OutOctets from /proc/net/netstat).
server_outoctets() {
  dc exec -T server sh -c \
    "awk '/^IpExt:/{n++; if(n==1){for(i=1;i<=NF;i++) if(\$i==\"OutOctets\") c=i} else print \$c}' /proc/net/netstat"
}

echo "[*] (Re)starting server with CC_ALGO=${CC_ALGO}..."
CC_ALGO="${CC_ALGO}" dc up -d --force-recreate server >/dev/null
sleep 1
dc exec -T server sh -c 'command -v nstat >/dev/null' || true

# --- shape the path (best effort; missing on Docker Desktop's stripped kernel) ---
SHAPED=1
echo "[*] Shaping server egress: delay=${DELAY}ms loss=${LOSS}% (no rate cap)..."
dc exec -T server tc qdisc del dev eth0 root 2>/dev/null || true
if dc exec -T server tc qdisc add dev eth0 root netem delay "${DELAY}ms" loss "${LOSS}%" limit 100000 2>/dev/null; then
  dc exec -T server tc qdisc show dev eth0
else
  SHAPED=0
  echo "[!] netem is unavailable on this kernel (e.g. Docker Desktop LinuxKit)."
  echo "    Running a CORRECTNESS-ONLY pass with no bottleneck: the attack tool"
  echo "    is exercised end-to-end, but the honest-vs-attack inflation ratio is"
  echo "    only meaningful on a real kernel. Get the real numbers from CI"
  echo "    (ubuntu-latest) -- same story as the BBR limitation. See README.md."
fi

# --- honest baseline: real kernel-TCP client pulls for DURATION seconds ---
echo "[*] Honest baseline: kernel-TCP pull from observer (${DURATION}s)..."
H0=$(server_outoctets)
dc exec -T observer sh -c "timeout ${DURATION} nc server 5000 > /dev/null" || true
H1=$(server_outoctets)
HON_MBIT=$(python3 -c "print(f'{max($H1-$H0,0)*8/($DURATION*1e6):.2f}')")
echo "    honest server egress: ${HON_MBIT} Mbit/s"

sleep 2

# --- attack: optimistic-ACK tool for DURATION seconds, with a mid-run ss snapshot ---
echo "[*] Optimistic-ACK attack (${DURATION}s)..."
A0=$(server_outoctets)
dc exec -T attacker /work/attack --target server --port 5000 --duration "${DURATION}" >/dev/null 2>&1 &
APID=$!
sleep "$(python3 -c "print(max(int($DURATION/2),2))")"
echo "[*] server ss -ti mid-attack (expect huge cwnd, tiny rtt):"
dc exec -T server ss -tin dst attacker 2>/dev/null | sed 's/^/    /' | head -3 || true
wait "${APID}" 2>/dev/null || true
A1=$(server_outoctets)
ATK_MBIT=$(python3 -c "print(f'{max($A1-$A0,0)*8/($DURATION*1e6):.2f}')")
echo "    attack server egress: ${ATK_MBIT} Mbit/s"

# --- verdict ---
INFL=$(python3 -c "print(f'{(($ATK_MBIT)/($HON_MBIT)) if $HON_MBIT>0 else 0:.2f}')")
HDR="cc_algo,shaped,delay_ms,loss_pct,duration_s,honest_mbit,attack_mbit,inflation"
[ -f data/attack_results.csv ] || echo "$HDR" > data/attack_results.csv
echo "${CC_ALGO},${SHAPED},${DELAY},${LOSS},${DURATION},${HON_MBIT},${ATK_MBIT},${INFL}" >> data/attack_results.csv

echo
echo "=============================================================="
echo " honest baseline : ${HON_MBIT} Mbit/s"
echo " under attack    : ${ATK_MBIT} Mbit/s"
echo " inflation factor: ${INFL}x   (gate: >= ${MIN_INFLATION}x)"
echo "=============================================================="
if [ "${SHAPED}" -eq 0 ]; then
  echo "RESULT: correctness-only (no netem on this kernel) -- not a pass/fail gate."
  exit 0
fi
python3 -c "import sys; sys.exit(0 if $INFL >= $MIN_INFLATION else 1)" \
  && echo "RESULT: PASS" || { echo "RESULT: FAIL"; exit 1; }
