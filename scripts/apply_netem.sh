#!/usr/bin/env bash
# Apply (or replace) a netem bottleneck shape on one service's eth0.
#
# Usage: ./scripts/apply_netem.sh <service> <rate_mbit> <delay_ms> <queue_limit>
# Example: ./scripts/apply_netem.sh attacker 10 20 50
set -euo pipefail

SERVICE="${1:-attacker}"
RATE="${2:-10}"
DELAY="${3:-20}"
LIMIT="${4:-50}"

echo "[*] Clearing any existing qdisc on '${SERVICE}' eth0..."
docker compose exec "${SERVICE}" tc qdisc del dev eth0 root 2>/dev/null || true

echo "[*] Applying netem: rate=${RATE}mbit delay=${DELAY}ms limit=${LIMIT} on '${SERVICE}'..."
docker compose exec "${SERVICE}" tc qdisc add dev eth0 root netem delay "${DELAY}ms" rate "${RATE}mbit" limit "${LIMIT}"

echo "[*] Current qdisc on '${SERVICE}':"
docker compose exec "${SERVICE}" tc qdisc show dev eth0
