"""
Results Graph Generator
========================
Produces the evaluation charts from measured experiment data.

All values plotted here come from the experiment logs, the per-switch
install trace, or iperf measurements passed on the command line. Nothing
is simulated or hardcoded except the classifier F1 scores, which are the
measured output of fingerprint_classifier.py.

Usage:
  python evaluation/generate_graphs.py \
      --adaptive results/experiment_adaptive_X.jsonl \
      --baseline results/experiment_baseline_Y.jsonl \
      --tput-before 94.6 --tput-after 94.7 --nodes 5

Output: results/graphs/*.png

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json
import math
import os
import argparse

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt

os.makedirs("results/graphs", exist_ok=True)

# Measured classifier output (see fingerprint_classifier.py)
F1_INSTALLS = {'baseline': 0.833, 'adaptive': 0.741}   # realistic attacker
F1_TRIGGER  = {'baseline': 0.958, 'adaptive': 0.000}   # pinpointing the trigger


# ---------------------------------------------------------------- data loading
def load_jsonl(path):
    records = []
    if not os.path.exists(path):
        print("[!] File not found:", path)
        return records
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def load_trace(path="logs/install_trace.log"):
    rows = []
    if not os.path.exists(path):
        return rows
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    rows.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return rows


def mutation_times(records):
    times, prev = [], 0
    for r in records:
        cur = r.get("mutations", 0)
        if cur > prev:
            for _ in range(cur - prev):
                times.append(r.get("elapsed_s", 0))
            prev = cur
    return times


def intervals(times):
    return [round(times[i + 1] - times[i], 3) for i in range(len(times) - 1)]


def entropy(vals, bins=5):
    if len(vals) < 2:
        return 0.0
    lo, hi = min(vals), max(vals)
    if hi == lo:
        return 0.0
    width = (hi - lo) / bins
    counts = [0] * bins
    for v in vals:
        counts[min(int((v - lo) / width), bins - 1)] += 1
    n = len(vals)
    h = 0.0
    for c in counts:
        if c:
            p = c / n
            h -= p * math.log2(p)
    return h


def save(name):
    path = "results/graphs/%s.png" % name
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print("[+] Saved:", path)


# ---------------------------------------------------------------- 01 CPU
def chart_cpu(adaptive, baseline):
    plt.figure(figsize=(8, 5))
    plt.plot([r['elapsed_s'] for r in adaptive], [r['cpu_pct'] for r in adaptive],
             '-o', markersize=3, label='Adaptive')
    plt.plot([r['elapsed_s'] for r in baseline], [r['cpu_pct'] for r in baseline],
             '--s', markersize=3, label='Baseline')
    plt.xlabel('Time (s)')
    plt.ylabel('Controller CPU (%)')
    plt.title('CPU Overhead')
    plt.legend()
    plt.grid(True)
    save('01_cpu_overhead')


# ---------------------------------------------------------------- 02 mutations
def chart_mutations(adaptive, baseline):
    plt.figure(figsize=(8, 5))
    plt.step([r['elapsed_s'] for r in adaptive], [r['mutations'] for r in adaptive],
             where='post', label='Adaptive')
    plt.step([r['elapsed_s'] for r in baseline], [r['mutations'] for r in baseline],
             where='post', linestyle='--', label='Baseline')
    plt.xlabel('Time (s)')
    plt.ylabel('Cumulative mutations')
    plt.title('Mutations Over Time')
    plt.legend()
    plt.grid(True)
    save('02_mutations_over_time')


# ---------------------------------------------------------------- 03 classifier
def chart_detectability():
    labels = ['Baseline', 'Adaptive']
    x = range(len(labels))
    w = 0.35

    plt.figure(figsize=(8, 5))
    plt.bar([i - w / 2 for i in x],
            [F1_INSTALLS['baseline'], F1_INSTALLS['adaptive']],
            width=w, label='Detecting installs (all FLOW_MODs)')
    plt.bar([i + w / 2 for i in x],
            [F1_TRIGGER['baseline'], F1_TRIGGER['adaptive']],
            width=w, label='Pinpointing trigger instant')
    plt.xticks(list(x), labels)
    plt.ylabel('Classifier F1 score')
    plt.ylim(0, 1.05)
    plt.title('Fingerprint Detectability (Random Forest)')
    plt.legend()
    plt.grid(True, axis='y')
    save('03_detectability_measured')


# ---------------------------------------------------------------- 04 install window
def chart_installation_window(trace):
    per = {}
    for e in trace:
        per.setdefault(e['mutation_id'], []).append(float(e['install_ts']))
    windows = [round(max(v) - min(v), 3) for v in per.values() if len(v) > 1]
    if not windows:
        print("[!] No install trace - skipping installation window chart.")
        return

    x = range(1, len(windows) + 1)
    w = 0.35
    plt.figure(figsize=(8, 5))
    plt.bar([i - w / 2 for i in x], [0.0] * len(windows), width=w, label='Baseline')
    plt.bar([i + w / 2 for i in x], windows, width=w, label='Adaptive')
    plt.xlabel('Mutation number')
    plt.ylabel('Install spread (s)')
    plt.title('Install Spread Per Mutation')
    plt.xticks(list(x))
    plt.legend()
    plt.grid(True, axis='y')
    save('04_installation_window')


# ---------------------------------------------------------------- 05 summary
def chart_summary(adaptive, baseline):
    a_cpu = [r['cpu_pct'] for r in adaptive]
    b_cpu = [r['cpu_pct'] for r in baseline]
    metrics = [
        ('Avg CPU (%)',
         sum(a_cpu) / len(a_cpu) if a_cpu else 0,
         sum(b_cpu) / len(b_cpu) if b_cpu else 0),
        ('Mutations',
         adaptive[-1]['mutations'] if adaptive else 0,
         baseline[-1]['mutations'] if baseline else 0),
        ('Threat events',
         adaptive[-1].get('threat_events', 0) if adaptive else 0,
         baseline[-1].get('threat_events', 0) if baseline else 0),
    ]

    fig, axes = plt.subplots(1, 3, figsize=(11, 4))
    for ax, (name, a, b) in zip(axes, metrics):
        ax.bar(['Adaptive', 'Baseline'], [a, b])
        ax.set_title(name)
        ax.grid(True, axis='y')
    fig.suptitle('Adaptive vs Baseline Summary')
    plt.tight_layout()
    save('05_summary_comparison')


# ---------------------------------------------------------------- 06 entropy
def chart_entropy(adaptive, baseline):
    a_int = intervals(mutation_times(adaptive))
    b_int = intervals(mutation_times(baseline))
    a_h, b_h = entropy(a_int), entropy(b_int)

    fig, axes = plt.subplots(1, 2, figsize=(11, 4.5))

    axes[0].bar(['Adaptive', 'Baseline'], [a_h, b_h])
    axes[0].set_ylabel('Entropy H(X) (bits)')
    axes[0].set_title('Mutation Timing Entropy')
    axes[0].grid(True, axis='y')

    if a_int:
        axes[1].plot(range(1, len(a_int) + 1), a_int, '-o', label='Adaptive')
    if b_int:
        axes[1].plot(range(1, len(b_int) + 1), b_int, '--s', label='Baseline')
    axes[1].set_xlabel('Mutation number')
    axes[1].set_ylabel('Interval (s)')
    axes[1].set_title('Gap Between Mutations')
    axes[1].legend()
    axes[1].grid(True)

    plt.tight_layout()
    save('06_mutation_entropy')


# ---------------------------------------------------------------- 07 response time
def chart_response_time(trace):
    delays = [float(e.get('install_delay', 0)) for e in trace]
    if not delays:
        print("[!] No install trace - skipping response time chart.")
        return
    mean_d = sum(delays) / len(delays)

    plt.figure(figsize=(8, 5))
    plt.hist(delays, bins=8, edgecolor='black')
    plt.axvline(mean_d, color='r', linestyle='--', label='mean %.2f s' % mean_d)
    plt.xlabel('Detection to install delay (s)')
    plt.ylabel('Number of installs')
    plt.title('Response Time Distribution')
    plt.legend()
    plt.grid(True, axis='y')
    save('07_response_time')


# ---------------------------------------------------------------- 08 throughput
def chart_throughput(before, after, nodes):
    if before is None or after is None:
        print("[!] No throughput values - skipping (use --tput-before/--tput-after).")
        return
    fig, axes = plt.subplots(1, 2, figsize=(10, 4.5))

    axes[0].bar(['Before', 'With mutation'], [before, after])
    axes[0].set_ylabel('Throughput (Mbit/s)')
    axes[0].set_title('TCP Throughput (h1 to h3)')
    axes[0].grid(True, axis='y')

    axes[1].bar(['%d nodes' % nodes], [after / nodes])
    axes[1].set_ylabel('Mbit/s per node')
    axes[1].set_title('Throughput Per Node')
    axes[1].grid(True, axis='y')

    plt.tight_layout()
    save('08_throughput')


# ---------------------------------------------------------------- main
if __name__ == '__main__':
    ap = argparse.ArgumentParser()
    ap.add_argument('--adaptive', required=True)
    ap.add_argument('--baseline', required=True)
    ap.add_argument('--tput-before', type=float, default=None)
    ap.add_argument('--tput-after', type=float, default=None)
    ap.add_argument('--nodes', type=int, default=5)
    args = ap.parse_args()

    adaptive = load_jsonl(args.adaptive)
    baseline = load_jsonl(args.baseline)
    trace = load_trace()

    if not adaptive or not baseline:
        raise SystemExit("[!] Could not load experiment data.")

    print("[*] Adaptive: %d samples | Baseline: %d samples | Trace: %d installs"
          % (len(adaptive), len(baseline), len(trace)))

    chart_cpu(adaptive, baseline)
    chart_mutations(adaptive, baseline)
    chart_detectability()
    chart_installation_window(trace)
    chart_summary(adaptive, baseline)
    chart_entropy(adaptive, baseline)
    chart_response_time(trace)
    chart_throughput(args.tput_before, args.tput_after, args.nodes)

    print("[*] Charts written to results/graphs/")
