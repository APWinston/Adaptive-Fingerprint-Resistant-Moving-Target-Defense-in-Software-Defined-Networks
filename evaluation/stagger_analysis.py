"""
Staggered Installation Analysis (MEASURED)
==========================================
Reports the real per-switch installation timing recorded in
logs/install_trace.log during an experiment run.

HISTORY / WHY THIS WAS REWRITTEN
--------------------------------
An earlier version of this script did not measure anything. It called
simulate_baseline_install() and simulate_adaptive_install(), which invented
timings with random numbers, and it hardcoded the baseline to install at
t=0.000. It then derived a "detectability score" of 1000 vs 1.6 and a
"613x fingerprint resistance" figure from those invented numbers.

That figure was an artefact of the simulation, not a result. Empirical
testing with a real Random Forest classifier later contradicted it: under a
realistic attacker the baseline scored F1 = 0.833 and the adaptive system
F1 = 0.741 - a modest reduction, not a 613-fold one.

This version therefore reports only what the install trace actually
recorded. For fingerprint resistance, use fingerprint_classifier.py, which
trains a real classifier on captured traffic.

Usage:
  python evaluation/stagger_analysis.py
  python evaluation/stagger_analysis.py --trace results/install_trace_adaptive.log

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json, os, argparse, statistics
from collections import defaultdict


def load_trace(path):
    if not os.path.exists(path):
        print(f"[!] Trace not found: {path}")
        return []
    rows = []
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def analyse(rows):
    """Group installs by mutation and measure the real spread of each."""
    by_mutation = defaultdict(list)
    for r in rows:
        by_mutation[r["mutation_id"]].append(r)

    print(f"\n{'Mutation':>9}  {'Switches':>8}  {'Window (s)':>10}   Install delays")
    print("-" * 64)

    windows = []
    for mid in sorted(by_mutation):
        entries = sorted(by_mutation[mid], key=lambda e: e["install_ts"])
        delays = [e["install_delay"] for e in entries]
        window = max(e["install_ts"] for e in entries) - min(e["install_ts"] for e in entries)
        windows.append(window)
        detail = "  ".join(f"s{e['switch']}@+{e['install_delay']:.2f}s" for e in entries)
        print(f"{mid:>9}  {len(entries):>8}  {window:>10.3f}   {detail}")

    return windows


def main():
    ap = argparse.ArgumentParser(description="Measured install timing (Group 46)")
    ap.add_argument("--trace", default="logs/install_trace.log")
    args = ap.parse_args()

    rows = load_trace(args.trace)
    if not rows:
        print("[!] Nothing to analyse. Run an experiment first.")
        return

    modes = {r.get("mode", "unknown") for r in rows}
    print("\n" + "=" * 64)
    print("  MEASURED INSTALLATION TIMING  -  Group 46")
    print("=" * 64)
    print(f"  Trace : {args.trace}")
    print(f"  Mode  : {', '.join(modes)}")
    print(f"  Events: {len(rows)} switch installs")

    windows = analyse(rows)
    delays = [r["install_delay"] for r in rows]

    print("-" * 64)
    print(f"  Install delay after trigger : min {min(delays):.3f}s  "
          f"max {max(delays):.3f}s  mean {statistics.mean(delays):.3f}s")
    if windows:
        print(f"  Per-mutation spread         : min {min(windows):.3f}s  "
              f"max {max(windows):.3f}s  mean {statistics.mean(windows):.3f}s")
    print("=" * 64)
    print("\n  This reports MEASURED timing only. It does not estimate")
    print("  fingerprint resistance - a timing spread is not evidence that")
    print("  an attacker cannot detect the mutation. For that, run:")
    print("      python fingerprint_classifier.py --pcap <capture> \\")
    print("             --trace <install_trace> --label-installs --any-priority")
    print()


if __name__ == "__main__":
    main()
