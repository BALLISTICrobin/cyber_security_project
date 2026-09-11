#!/usr/bin/env python3
"""
Milestone 3 sweep: run the optimistic-ACK attack across the matrix of
congestion-control algorithm x TCP timestamps x SACK, and record the egress
amplification and peak congestion window for each combination.

For every congestion-control algorithm it first measures an honest kernel-TCP
baseline over the same shaped (lossy, delayed) path, then runs the attack once
per (timestamps, sack) setting and divides. The headline result is the pattern:
CUBIC and Reno amplify without bound (their window ignores nothing but ACKs),
while BBR -- which paces from a bandwidth/RTT model rather than trusting ACKs --
stays bounded.

Writes data/sweep_results.json. Needs a real kernel with netem (and tcp_bbr for
the BBR rows): run it in CI (ubuntu-latest), same as the M2 gate and the BBR
comparison. On a kernel without netem the numbers are meaningless and the script
says so.

Usage: python3 scripts/sweep.py
Env:   SWEEP_DURATION (s, default 10), SWEEP_DELAY (ms, 20), SWEEP_LOSS (%, 2)
"""
import itertools
import json
import os
import re
import subprocess
import sys
import time

DURATION = int(os.environ.get("SWEEP_DURATION", "10"))
DELAY = os.environ.get("SWEEP_DELAY", "20")
LOSS = os.environ.get("SWEEP_LOSS", "2")
ALGOS = os.environ.get("SWEEP_ALGOS", "reno cubic bbr").split()

CWND_RE = re.compile(r"\bcwnd:(\d+)")
SST_RE = re.compile(r"\bssthresh:(\d+)")


def dc(args, capture=False, check=True):
    cmd = ["docker", "compose"] + args
    if capture:
        return subprocess.run(cmd, capture_output=True, text=True).stdout
    return subprocess.run(cmd, stdout=subprocess.DEVNULL,
                          stderr=subprocess.DEVNULL, check=False).returncode


def outoctets():
    """Server bytes injected onto the wire (IpExt OutOctets)."""
    awk = (r"""awk '/^IpExt:/{n++; if(n==1){for(i=1;i<=NF;i++) """
           r"""if($i=="OutOctets") c=i} else print $c}' /proc/net/netstat""")
    out = dc(["exec", "-T", "server", "sh", "-c", awk], capture=True).strip()
    try:
        return int(out.splitlines()[-1])
    except (ValueError, IndexError):
        return 0


def sample_peak_cwnd(peer, stop_at):
    """Poll ss on the server until stop_at, return (peak_cwnd, min_ssthresh)."""
    peak, min_sst = 0, None
    while time.monotonic() < stop_at:
        out = dc(["exec", "-T", "server", "ss", "-tin", "dst", peer], capture=True)
        for m in CWND_RE.finditer(out):
            peak = max(peak, int(m.group(1)))
        for m in SST_RE.finditer(out):
            v = int(m.group(1))
            min_sst = v if min_sst is None else min(min_sst, v)
        time.sleep(0.25)
    return peak, min_sst


def measure(flow_cmd, peer):
    """Run flow_cmd (a docker compose argv) for DURATION s while sampling the
    server socket; return dict with egress Mbit/s, peak cwnd, min ssthresh."""
    before = outoctets()
    proc = subprocess.Popen(["docker", "compose"] + flow_cmd,
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    peak, min_sst = sample_peak_cwnd(peer, time.monotonic() + DURATION - 0.5)
    proc.wait()
    after = outoctets()
    mbit = max(after - before, 0) * 8 / (DURATION * 1e6)
    return {"mbit": round(mbit, 2), "peak_cwnd": peak, "min_ssthresh": min_sst}


def shape():
    dc(["exec", "-T", "server", "tc", "qdisc", "del", "dev", "eth0", "root"])
    rc = dc(["exec", "-T", "server", "tc", "qdisc", "add", "dev", "eth0", "root",
             "netem", "delay", f"{DELAY}ms", "loss", f"{LOSS}%", "limit", "100000"])
    return rc == 0


def main():
    rows = []
    shaped_ok = True
    for algo in ALGOS:
        print(f"\n=== congestion control: {algo} ===")
        subprocess.run(["docker", "compose", "up", "-d", "--force-recreate", "server"],
                       env={**os.environ, "CC_ALGO": algo},
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(1)
        if not shape():
            shaped_ok = False
            print("  [!] netem unavailable on this kernel -- numbers are not "
                  "meaningful here; run this in CI. Continuing anyway.")

        honest = measure(
            ["exec", "-T", "observer", "sh", "-c",
             f"timeout {DURATION} nc server 5000 > /dev/null"],
            "observer")
        print(f"  honest baseline: {honest['mbit']} Mbit/s "
              f"(peak cwnd {honest['peak_cwnd']})")

        for ts, sack in itertools.product([False, True], [False, True]):
            flags = ["--target", "server", "--port", "5000",
                     "--duration", str(DURATION)]
            if ts:
                flags.append("--timestamps")
            if sack:
                flags.append("--sack")
            atk = measure(["exec", "-T", "attacker", "/work/attack"] + flags,
                          "attacker")
            ampl = round(atk["mbit"] / honest["mbit"], 2) if honest["mbit"] else 0
            row = {
                "cc": algo, "timestamps": ts, "sack": sack,
                "honest_mbit": honest["mbit"], "attack_mbit": atk["mbit"],
                "amplification": ampl,
                "attack_peak_cwnd": atk["peak_cwnd"],
                "attack_min_ssthresh": atk["min_ssthresh"],
                "honest_peak_cwnd": honest["peak_cwnd"],
            }
            rows.append(row)
            print(f"  ts={int(ts)} sack={int(sack)}: {atk['mbit']} Mbit/s "
                  f"peak cwnd {atk['peak_cwnd']} -> {ampl}x amplification")

    os.makedirs("data", exist_ok=True)
    with open("data/sweep_results.json", "w") as f:
        json.dump({"duration_s": DURATION, "delay_ms": DELAY, "loss_pct": LOSS,
                   "shaped": shaped_ok, "rows": rows}, f, indent=2)
    print("\n[*] wrote data/sweep_results.json")

    # Sanity summary: CUBIC/Reno should dwarf BBR.
    def avg(cc):
        xs = [r["amplification"] for r in rows if r["cc"] == cc]
        return sum(xs) / len(xs) if xs else 0
    for cc in ALGOS:
        print(f"    mean amplification {cc}: {avg(cc):.1f}x")
    if not shaped_ok:
        print("RESULT: correctness-only (no netem) -- not a pass/fail gate.")
        return 0
    loss_based = [cc for cc in ("cubic", "reno") if cc in ALGOS]
    ok = all(avg(cc) >= 3.0 for cc in loss_based)
    if "bbr" in ALGOS and loss_based:
        ok = ok and avg("bbr") < min(avg(cc) for cc in loss_based)
    print("RESULT:", "PASS" if ok else "FAIL")
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
