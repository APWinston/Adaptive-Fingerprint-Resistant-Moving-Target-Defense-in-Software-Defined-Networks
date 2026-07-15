"""
KPI Calculator
==============
Computes the evaluation KPIs for the Adaptive Fingerprint-Resistant MTD
project from the logs and the per-switch install trace.

KPIs reported here:
  1. Cooldown pass rate            -> mutations / threshold crossings
  2. Scalability                   -> Throughput / Number of Nodes
  3. Mutation Effectiveness        -> Shannon Entropy H(X)
  4. Response Time                 -> mean(install_ts - trigger_ts)
  5. Install window                -> measured spread of a staggered install

FINGERPRINT RESISTANCE IS NOT COMPUTED HERE - AND THAT IS DELIBERATE
--------------------------------------------------------------------
An earlier version of this script reported an Adjusted Rand Index (ARI) as
a "fingerprint resistance" KPI. That metric compared the true mutation
instants against a hand-written model of an attacker that only flagged
perfectly synchronised installation bursts. A staggered system scores ~0
under that model by construction, so the metric assumed its own conclusion.
It produced ARI = 0.00 and an accompanying "613x more resistant" claim.

Empirical testing contradicted both. Training a real Random Forest on
captured control-plane traffic, under an attacker that sees all FLOW_MOD
messages with no priority hint, gave:

    baseline  F1 = 0.833      adaptive  F1 = 0.741

- a modest reduction in detectability, not a 613-fold one. On the narrower
task of pinpointing the mutation TRIGGER instant the gap is real and large
(baseline F1 = 0.958, adaptive F1 = 0.000), but that is a narrower claim
than "fingerprint resistant".

Fingerprint resistance must therefore be measured with
fingerprint_classifier.py against a real capture, not modelled here.

Usage:
  python evaluation/compute_kpis.py
  python evaluation/compute_kpis.py --throughput 95.0 --nodes 5

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json, os, glob, math, argparse
from collections import Counter

# ------------------------------------------------------------------ helpers
def load_jsonl(path):
    out = []
    if not path or not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out

def latest(pattern):
    files = glob.glob(pattern)
    return max(files, key=os.path.getmtime) if files else None

def mutation_times_from_experiment(records):
    times, prev = [], 0
    for r in records:
        cur = r.get("mutations", 0)
        if cur > prev:
            for _ in range(cur - prev):
                times.append(r.get("elapsed_s", 0))
            prev = cur
    return times

def intervals_of(times):
    return [round(times[i+1] - times[i], 3) for i in range(len(times) - 1)]

# ------------------------------------------------------------------ KPI 4: entropy
def shannon_entropy(intervals, bins=5):
    if len(intervals) < 2:
        return None
    lo, hi = min(intervals), max(intervals)
    if hi == lo:
        return 0.0
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in intervals:
        counts[min(int((v - lo) / width), bins - 1)] += 1
    n = len(intervals)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return round(h, 3)

# ------------------------------------------------------------------ KPI 5: response time
def install_window_from_trace(trace):
    """Measured spread between the first and last switch install per mutation."""
    per = {}
    for e in trace:
        per.setdefault(e["mutation_id"], []).append(float(e["install_ts"]))
    windows = [max(v) - min(v) for v in per.values() if len(v) > 1]
    if not windows:
        return None, 0
    return round(sum(windows) / len(windows), 3), len(windows)


def response_time_from_trace(trace):
    """Mean install delay = install_ts - trigger_ts across all switch installs."""
    deltas = [e["install_delay"] for e in trace if e.get("install_delay", -1) >= 0]
    if not deltas:
        return None, 0
    return round(sum(deltas) / len(deltas), 3), len(deltas)

# ------------------------------------------------------------------ cooldown ratio
def cooldown_pass_rate(records):
    """
    Fraction of threshold crossings that actually produced a mutation, i.e.
    how many got past the cooldown. NOT a security metric.

    This function used to be called rdr() and its output was reported as the
    Reconnaissance Disruption Rate. It never measured that. It computes
    mutations / threat_events, so its value is driven by how many times the
    threshold was crossed - it read 0.50 on a run with ~10 crossings and
    0.004 on a run with ~2000. The defence did not change; the denominator did.

    True RDR for this system is ~0: the attacker scans REAL addresses, and the
    mutation only rewrites traffic aimed at VIRTUAL addresses, so scans return
    complete and accurate results (nmap reported every port on every run).
    Measuring a real RDR requires an attack model in which the attacker only
    ever learns virtual addresses, as in OF-RHM.
    """
    if not records:
        return None
    last = records[-1]
    threats   = last.get("threat_events", 0)
    mutations = last.get("mutations", 0)
    if threats <= 0:
        return None
    return round(mutations / threats, 4)


# ------------------------------------------------------------------ report
def fmt(v, suffix=""):
    return "N/A" if v is None else (f"{v}{suffix}")

def main():
    ap = argparse.ArgumentParser(description="MTD KPI Calculator (Group 46)")
    ap.add_argument("--adaptive", default=None)
    ap.add_argument("--baseline", default=None)
    ap.add_argument("--install-trace", default="logs/install_trace.log")
    ap.add_argument("--throughput", type=float, default=None)
    ap.add_argument("--nodes", type=int, default=None)
    ap.add_argument("--scans", type=int, default=None)
    args = ap.parse_args()

    adaptive_file = args.adaptive or latest("results/experiment_adaptive_*.jsonl")
    baseline_file = args.baseline or latest("results/experiment_baseline_*.jsonl")
    adaptive = load_jsonl(adaptive_file)
    baseline = load_jsonl(baseline_file)
    trace    = load_jsonl(args.install_trace)

    a_int = intervals_of(mutation_times_from_experiment(adaptive))
    b_int = intervals_of(mutation_times_from_experiment(baseline))

    a_entropy = shannon_entropy(a_int)
    b_entropy = shannon_entropy(b_int)
    a_cool = cooldown_pass_rate(adaptive)
    b_cool = cooldown_pass_rate(baseline)
    rt_mean, rt_n = response_time_from_trace(trace)
    win_mean, win_n = install_window_from_trace(trace)
    scal = (round(args.throughput / args.nodes, 3)
            if args.throughput and args.nodes else None)

    line = "=" * 64
    print("\n" + line)
    print("  MTD-SDN KPI REPORT  -  Group 46")
    print(line)
    print(f"  Adaptive data: {adaptive_file or 'not found'}")
    print(f"  Baseline data: {baseline_file or 'not found'}")
    print(f"  Install trace: {args.install_trace if trace else 'not found'} "
          f"({len(trace)} install events)")
    print(line)

    print(f"\n{'KPI':<34}{'Adaptive':>14}{'Baseline':>14}")
    print("-" * 64)
    print(f"{'1. Cooldown pass rate (not RDR)':<34}{fmt(a_cool):>14}{fmt(b_cool):>14}")
    print(f"{'2. Scalability (Mbps/node)':<34}{fmt(scal):>14}{fmt(scal):>14}")
    print(f"{'3. Mutation Entropy H(X) bits':<34}{fmt(a_entropy):>14}{fmt(b_entropy):>14}")
    print(f"{'4. Response Time (s)':<34}{fmt(rt_mean):>14}{'n/a':>14}")
    print(f"{'5. Install window (s, measured)':<34}{fmt(win_mean):>14}{'n/a':>14}")
    print("-" * 64)

    print("\nINTERPRETATION")
    print("-" * 64)
    if a_cool is not None:
        print(f"  Cooldown pass rate = {a_cool} ({a_cool*100:.1f}% of threshold")
        print("       crossings produced a mutation; the rest hit the cooldown).")
        print("       This is NOT the Reconnaissance Disruption Rate.")
    print("")
    print("  RECONNAISSANCE DISRUPTION (RDR) = ~0 for this attack model.")
    print("       The attacker scans real addresses; mutation only rewrites")
    print("       traffic to virtual addresses, so scans succeed intact.")
    print("       A real RDR needs an attacker that only learns virtual IPs.")
    if a_entropy is not None and b_entropy is not None:
        print(f"  Entropy: Adaptive={a_entropy} bits vs Baseline={b_entropy} bits.")
    if rt_mean is not None:
        print(f"  Response time = {rt_mean}s mean over {rt_n} switch installs.")
    if win_mean is not None:
        print(f"  Install window = {win_mean}s mean over {win_n} mutations.")
        print("       (Baseline installs simultaneously, so its window is ~0.000s.)")
    if scal is None:
        print("  Scalability: run 'iperf h1 h3' in Mininet, then re-run with")
        print("       --throughput <Mbps> --nodes <count>")
    print("-" * 64)
    print("  FINGERPRINT RESISTANCE is not reported here. Measure it with:")
    print("     python fingerprint_classifier.py --pcap <capture> \\")
    print("            --trace <install_trace> --label-installs --any-priority")
    print("  Measured result: baseline F1 = 0.833, adaptive F1 = 0.741")
    print(line + "\n")

if __name__ == "__main__":
    main()
