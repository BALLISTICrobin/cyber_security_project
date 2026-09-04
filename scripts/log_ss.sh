#!/usr/bin/env bash
# Periodically snapshot `ss -ti` for a given peer on a given service, to a
# CSV file inside the shared /data volume (usable from M2 onward to plot
# cwnd/rtt over time during an attack run).
#
# Usage: ./scripts/log_ss.sh <service> <peer> <duration_s> <interval_s>
# Example: ./scripts/log_ss.sh server observer 15 1
set -euo pipefail

SERVICE="${1:-server}"
PEER="${2:-observer}"
DURATION="${3:-15}"
INTERVAL="${4:-1}"
OUTFILE="/data/ss_log_${SERVICE}_$(date +%s).csv"

echo "[*] Logging 'ss -ti dst ${PEER}' on '${SERVICE}' every ${INTERVAL}s for ${DURATION}s..."
docker compose exec "${SERVICE}" bash -c "
  echo 'timestamp,ss_output' > ${OUTFILE}
  end=\$((\$(date +%s) + ${DURATION}))
  while [ \$(date +%s) -lt \$end ]; do
    ts=\$(date +%s.%N)
    line=\$(ss -ti dst ${PEER} | tr '\n' ' ')
    echo \"\${ts},\${line}\" >> ${OUTFILE}
    sleep ${INTERVAL}
  done
"
echo "[*] Log saved to ./data/$(basename "${OUTFILE}")"
