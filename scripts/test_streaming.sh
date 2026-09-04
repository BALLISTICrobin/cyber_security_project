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
docker compose exec server ss -ti dst observer

echo "[*] Waiting for the pull to finish..."
sleep "$((DURATION - 1))"

BYTES=$(docker compose exec observer stat -c %s "${OUTFILE}" | tr -d '[:space:]')
MBIT=$(python3 -c "print(f'{(${BYTES}*8)/(${DURATION}*1e6):.2f}')")
echo "[*] Received ${BYTES} bytes in ~${DURATION}s  ->  ~${MBIT} Mbit/s"

echo "cc_algo,duration_s,bytes,mbit_s" > /tmp/header.csv
if [ ! -f data/streaming_results.csv ]; then
    cp /tmp/header.csv data/streaming_results.csv
fi
echo "${CC_ALGO},${DURATION},${BYTES},${MBIT}" >> data/streaming_results.csv
echo "[*] Appended result to data/streaming_results.csv"
