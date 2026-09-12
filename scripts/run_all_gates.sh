#!/usr/bin/env bash
# Milestone 5 reproducibility gate: re-run every milestone's verification gate,
# end-to-end, from a fresh build. This is the "cold clone" test from
# PROJECT_IMPLEMENTATION_PLAN.md -- if this script passes on a machine neither
# of you has developed on, the project is genuinely reproducible, not just
# "works on my laptop."
#
# Deliberately does NOT use `set -e`: we want every gate to run even if an
# earlier one fails, so the summary at the end shows the true state of the
# whole project in one shot instead of stopping at the first red gate.
#
# Usage: ./scripts/run_all_gates.sh
set -uo pipefail

RESULTS=()
FAIL=0

section() {
    echo
    echo "################################################################"
    echo "# $1"
    echo "################################################################"
}

record() {
    local name="$1" rc="$2"
    if [ "$rc" -eq 0 ]; then
        RESULTS+=("PASS  ${name}")
    else
        RESULTS+=("FAIL  ${name}")
        FAIL=1
    fi
}

# Like record(), but treats a "RESULT: SKIP" in $3 (captured output) as its
# own status rather than PASS -- for gates that are legitimately
# host-dependent (e.g. bbr on a kernel without tcp_bbr) and should not count
# as either a pass or a failure of THIS project's correctness.
record_or_skip() {
    local name="$1" rc="$2" out="$3"
    if echo "${out}" | grep -q "RESULT: SKIP"; then
        RESULTS+=("SKIP  ${name}")
    else
        record "${name}" "${rc}"
    fi
}

mkdir -p data

section "Build all images"
docker compose build
record "build" $?

section "Bring up the testbed"
docker compose down >/dev/null 2>&1 || true
docker compose up -d
sleep 2
docker compose exec attacker ping -c 2 server >/dev/null
record "connectivity (attacker -> server)" $?

section "M0 -- baseline throughput (shaped link)"
./scripts/apply_netem.sh attacker 10 20 50 >/dev/null
./scripts/run_baseline.sh
record "M0 baseline" $?

section "M1 -- streaming server, CC_ALGO=cubic"
./scripts/test_streaming.sh cubic 8
record "M1 cubic" $?

section "M1 -- streaming server, CC_ALGO=reno"
./scripts/test_streaming.sh reno 8
record "M1 reno" $?

section "M1 -- streaming server, CC_ALGO=bbr (host-dependent; SKIP is not a failure)"
BBR_OUT=$(./scripts/test_streaming.sh bbr 8; echo "RC=$?")
echo "${BBR_OUT}"
BBR_RC=$(echo "${BBR_OUT}" | grep -oE 'RC=[0-9]+' | cut -d= -f2)
record_or_skip "M1 bbr" "${BBR_RC}" "${BBR_OUT}"

section "M2 -- optimistic-ACK attack vs. honest baseline"
CC_ALGO=cubic ./scripts/run_attack.sh 10 20 2
record "M2 attack (cubic)" $?

section "M3 -- CC x timestamps x SACK sweep (reno, cubic -- host-dependent subset)"
SWEEP_DURATION=6 SWEEP_ALGOS="reno cubic" python3 scripts/sweep.py
record "M3 sweep (reno,cubic)" $?
python3 scripts/plot_sweep.py
record "M3 plots" $?

section "M4 -- Sherwood skip-test defense"
./scripts/run_defense.sh 8
record "M4 defense" $?

section "Tear down"
docker compose down
record "teardown" $?

section "SUMMARY"
for r in "${RESULTS[@]}"; do echo "  ${r}"; done
echo
echo "Notes:"
echo "  - M1 bbr, and the bbr row of M3, are expected to report a non-PASS 'SKIP'"
echo "    style result on hosts without the tcp_bbr kernel module (e.g. Docker"
echo "    Desktop) -- that is documented, not a project bug. Real bbr numbers"
echo "    come from the GitHub Actions workflows (see README.md)."
echo "  - Raw results are under data/*.csv, data/*.json, data/*.png (git-ignored;"
echo "    regenerate them, don't commit them)."
echo

if [ "${FAIL}" -eq 0 ]; then
    echo "ALL GATES PASSED"
    exit 0
else
    echo "ONE OR MORE GATES FAILED -- see the sections above for details"
    exit 1
fi
