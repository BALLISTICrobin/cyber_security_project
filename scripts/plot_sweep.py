#!/usr/bin/env python3
"""
Milestone 3 dashboard: turn the sweep results (and an optional attack
time-series) into black-and-white figures for the report and CI artifacts.

Reads:
  data/sweep_results.json          (from scripts/sweep.py)
  data/attack_timeseries.csv       (optional, from `optack --log`)

Writes PNGs into data/:
  fig_amplification.png   egress amplification by CC, grouped by timestamps/SACK
  fig_peak_cwnd.png       peak congestion window by CC (log scale)
  fig_gap.png             acknowledged vs genuinely-delivered bytes over time

Everything is grayscale (hatch patterns / line styles, no colour) to match the
report. Needs matplotlib: pip install matplotlib.

Usage: python3 scripts/plot_sweep.py
"""
import csv
import json
import os
import sys

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

plt.rcParams.update({
    "font.family": "serif", "font.size": 10,
    "axes.grid": True, "grid.linestyle": ":", "grid.color": "0.8",
    "figure.facecolor": "white", "savefig.facecolor": "white",
})

DATA = "data"
HATCHES = {(False, False): "", (True, False): "///",
           (False, True): "...", (True, True): "xxx"}
LABELS = {(False, False): "plain", (True, False): "timestamps",
          (False, True): "SACK", (True, True): "timestamps+SACK"}


def load_sweep():
    with open(os.path.join(DATA, "sweep_results.json")) as f:
        return json.load(f)


def plot_amplification(sweep):
    rows = sweep["rows"]
    algos = list(dict.fromkeys(r["cc"] for r in rows))
    combos = [(False, False), (True, False), (False, True), (True, True)]
    n = len(combos)
    width = 0.8 / n
    fig, ax = plt.subplots(figsize=(7, 4))
    for i, combo in enumerate(combos):
        vals = [next((r["amplification"] for r in rows
                      if r["cc"] == a and r["timestamps"] == combo[0]
                      and r["sack"] == combo[1]), 0) for a in algos]
        xs = [j + i * width for j in range(len(algos))]
        ax.bar(xs, vals, width, label=LABELS[combo], color="white",
               edgecolor="black", hatch=HATCHES[combo])
    ax.axhline(3.0, color="black", linestyle="--", linewidth=0.8)
    ax.text(0, 3.1, "M2 gate = 3x", fontsize=8, style="italic")
    ax.set_xticks([j + 0.4 - width / 2 for j in range(len(algos))])
    ax.set_xticklabels([a.upper() for a in algos])
    ax.set_ylabel("egress amplification vs honest (x)")
    ax.set_title("Optimistic-ACK egress amplification by congestion control")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(DATA, "fig_amplification.png"), dpi=150)


def plot_peak_cwnd(sweep):
    rows = sweep["rows"]
    algos = list(dict.fromkeys(r["cc"] for r in rows))
    atk = [max((r["attack_peak_cwnd"] for r in rows if r["cc"] == a), default=0)
           for a in algos]
    hon = [max((r["honest_peak_cwnd"] for r in rows if r["cc"] == a), default=0)
           for a in algos]
    xs = range(len(algos))
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.bar([x - 0.2 for x in xs], atk, 0.4, label="under attack",
           color="0.3", edgecolor="black")
    ax.bar([x + 0.2 for x in xs], hon, 0.4, label="honest baseline",
           color="white", edgecolor="black", hatch="//")
    ax.set_yscale("log")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([a.upper() for a in algos])
    ax.set_ylabel("peak congestion window (segments, log scale)")
    ax.set_title("Peak congestion window: attack vs honest")
    ax.legend(frameon=False, fontsize=8)
    fig.tight_layout()
    fig.savefig(os.path.join(DATA, "fig_peak_cwnd.png"), dpi=150)


def plot_gap():
    path = os.path.join(DATA, "attack_timeseries.csv")
    if not os.path.exists(path):
        print("  (no attack_timeseries.csv; skipping the gap figure)")
        return
    t, deliv, acked = [], [], []
    with open(path) as f:
        for row in csv.DictReader(f):
            t.append(float(row["t_s"]))
            deliv.append(int(row["delivered_bytes"]) / 1e6)
            acked.append(int(row["acked_bytes"]) / 1e6)
    fig, ax = plt.subplots(figsize=(7, 4))
    ax.plot(t, acked, color="black", linestyle="-", label="acknowledged to server")
    ax.plot(t, deliv, color="black", linestyle="--", label="genuinely received")
    ax.fill_between(t, deliv, acked, color="0.85", label="optimistic gap")
    ax.set_xlabel("time (s)")
    ax.set_ylabel("cumulative bytes (MB)")
    ax.set_title("Acknowledged vs genuinely-delivered bytes (the attack)")
    ax.legend(frameon=False, fontsize=8, loc="upper left")
    fig.tight_layout()
    fig.savefig(os.path.join(DATA, "fig_gap.png"), dpi=150)


def main():
    try:
        sweep = load_sweep()
    except FileNotFoundError:
        sys.exit("data/sweep_results.json not found; run scripts/sweep.py first")
    plot_amplification(sweep)
    plot_peak_cwnd(sweep)
    plot_gap()
    print("[*] wrote figures to data/: fig_amplification.png, fig_peak_cwnd.png, "
          "fig_gap.png")


if __name__ == "__main__":
    main()
