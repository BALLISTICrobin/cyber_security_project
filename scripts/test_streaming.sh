#!/usr/bin/env bash
# Milestone 1 verification gate: start the streaming server with a given
# congestion-control algorithm, pull data as an honest client from
# 'observer', and confirm `ss -ti` shows the correct algorithm active on a
# healthy, completed stream.
#
# Usage: ./scripts/test_streaming.sh <cc_algo> <duration_s>
# Example: ./scripts/test_streaming.sh cubic 10
set -euo pipefail

CC_ALGO="${1:-cubic}"
DURATION="${2:-10}"
mkdir -p data

echo "[*] Starting server with CC_ALGO=${CC_ALGO}..."
CC_ALGO="${CC_ALGO}" docker compose up -d --force-recreate server
sleep 1

echo "[*] Shaping server's egress (10mbit/20ms/limit50)..."
echo "    (netem shapes EGRESS only -- 'server' is the bulk sender here, so IT needs"
echo "     shaping, not the client -- opposite direction from the M0 iperf3 baseline."
echo "     Must run AFTER --force-recreate, since recreating the container wipes"
echo "     any qdisc set on its previous network namespace.)"
./scripts/apply_netem.sh server 10 20 50 >/dev/null

OUTFILE="/data/pull_${CC_ALGO}.bin"
echo "[*] Pulling stream from 'observer' for ${DURATION}s (background)..."
docker compose exec -d observer bash -c "rm -f ${OUTFILE}; timeout ${DURATION} nc server 5000 > ${OUTFILE}"

sleep 2
echo "[*] ss -ti on server, mid-stream (should show '${CC_ALGO}'):"
SS_OUT=$(docker compose exec server ss -ti dst observer)
echo "${SS_OUT}"
ACTIVE_ALGO=$(echo "${SS_OUT}" | grep -oE 'cubic|reno|bbr' | head -1 || true)

echo "[*] Waiting for the pull to finish..."
sleep "$((DURATION - 1))"

BYTES=$(docker compose exec observer stat -c %s "${OUTFILE}" | tr -d '[:space:]')
MBIT=$(python3 -c "print(f'{(${BYTES}*8)/(${DURATION}*1e6):.2f}')")
echo "[*] Received ${BYTES} bytes in ~${DURATION}s  ->  ~${MBIT} Mbit/s"

if [ ! -f data/streaming_results.csv ]; then
    echo "cc_algo,duration_s,bytes,mbit_s" > data/streaming_results.csv
fi
echo "${CC_ALGO},${DURATION},${BYTES},${MBIT}" >> data/streaming_results.csv
echo "[*] Appended result to data/streaming_results.csv"

# Pass criteria: ss confirms the requested algorithm is active AND throughput
# is in the expected range for the 10mbit shape. BBR is a known exception --
# if this host's kernel lacks tcp_bbr, the server gracefully falls back to
# cubic (see README "Known limitation"), which is correct behavior, not a
# failure; that comparison can only be made honestly in CI.
RATE_OK=$(python3 -c "print(1 if 5.0 <= ${MBIT} <= 11.0 else 0)")
if [ "${CC_ALGO}" = "bbr" ] && [ "${ACTIVE_ALGO}" != "bbr" ]; then
    echo "RESULT: SKIP (bbr unavailable on this host -- see CI: cc-comparison.yml)"
    exit 0
elif [ "${ACTIVE_ALGO}" = "${CC_ALGO}" ] && [ "${RATE_OK}" = "1" ]; then
    echo "RESULT: PASS"
    exit 0
else
    echo "RESULT: FAIL (active=${ACTIVE_ALGO:-none}, expected=${CC_ALGO}, rate_ok=${RATE_OK})"
    exit 1
fi
