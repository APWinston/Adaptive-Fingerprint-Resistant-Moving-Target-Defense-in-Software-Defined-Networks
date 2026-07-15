"""
Results Graph Generator
========================
Generates all charts and graphs needed for the final report.

Charts produced:
  1. CPU overhead comparison (adaptive vs baseline)
  2. Mutations over time (adaptive vs baseline)
  3. Detectability score comparison (bar chart)
  4. Installation window spread (adaptive vs baseline)
  5. Threat detection timeline

Run:
  python evaluation/generate_graphs.py \
    --adaptive results/experiment_adaptive_1780746478.jsonl \
    --baseline results/experiment_baseline_1780747012.jsonl

Output: results/graphs/ folder (PNG files)

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json
import os
import argparse
import random
import math

os.makedirs("results/graphs", exist_ok=True)

# ── Try to import matplotlib ──────────────────────────────────────────────────
try:
    import matplotlib
    matplotlib.use('Agg')  # Non-interactive backend for VM
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True
except ImportError:
    HAS_MATPLOTLIB = False
    print("[!] matplotlib not found. Installing...")
    os.system("sudo pip3 install matplotlib")
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    import matplotlib.patches as mpatches
    HAS_MATPLOTLIB = True

ADAPTIVE_COLOR = "#2E75B6"
BASELINE_COLOR = "#C00000"
GRID_COLOR     = "#EEEEEE"

def load_jsonl(filepath):
    records = []
    if not os.path.exists(filepath):
        print(f"[!] File not found: {filepath}")
        return records
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    records.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return records


def style_ax(ax, title, xlabel, ylabel):
    ax.set_title(title, fontsize=13, fontweight='bold', pad=12)
    ax.set_xlabel(xlabel, fontsize=11)
    ax.set_ylabel(ylabel, fontsize=11)
    ax.grid(True, color=GRID_COLOR, linewidth=0.8)
    ax.spines['top'].set_visible(False)
    ax.spines['right'].set_visible(False)


# ── Chart 1: CPU Overhead Over Time ──────────────────────────────────────────
def chart_cpu(adaptive, baseline):
    fig, ax = plt.subplots(figsize=(10, 5))

    a_times = [r['elapsed_s'] for r in adaptive]
    a_cpu   = [r['cpu_pct']   for r in adaptive]
    b_times = [r['elapsed_s'] for r in baseline]
    b_cpu   = [r['cpu_pct']   for r in baseline]

    ax.plot(a_times, a_cpu, color=ADAPTIVE_COLOR, linewidth=2,
            label='Adaptive MTD', marker='o', markersize=3)
    ax.plot(b_times, b_cpu, color=BASELINE_COLOR, linewidth=2,
            label='Baseline MTD', marker='s', markersize=3, linestyle='--')

    ax.fill_between(a_times, a_cpu, alpha=0.1, color=ADAPTIVE_COLOR)
    ax.fill_between(b_times, b_cpu, alpha=0.1, color=BASELINE_COLOR)

    style_ax(ax, "CPU Overhead: Adaptive vs Baseline MTD",
             "Time (seconds)", "CPU Usage (%)")
    ax.legend(fontsize=10)

    # Annotations
    a_avg = sum(a_cpu) / len(a_cpu) if a_cpu else 0
    b_avg = sum(b_cpu) / len(b_cpu) if b_cpu else 0
    ax.axhline(a_avg, color=ADAPTIVE_COLOR, linestyle=':', alpha=0.5)
    ax.axhline(b_avg, color=BASELINE_COLOR, linestyle=':', alpha=0.5)
    ax.text(max(a_times)*0.8, a_avg+0.05, f'Avg {a_avg:.2f}%',
            color=ADAPTIVE_COLOR, fontsize=9)
    ax.text(max(b_times)*0.8, b_avg+0.05, f'Avg {b_avg:.2f}%',
            color=BASELINE_COLOR, fontsize=9)

    plt.tight_layout()
    path = "results/graphs/01_cpu_overhead.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {path}")


# ── Chart 2: Mutations Over Time ──────────────────────────────────────────────
def chart_mutations(adaptive, baseline):
    fig, ax = plt.subplots(figsize=(10, 5))

    a_times = [r['elapsed_s'] for r in adaptive]
    a_muts  = [r['mutations'] for r in adaptive]
    b_times = [r['elapsed_s'] for r in baseline]
    b_muts  = [r['mutations'] for r in baseline]

    ax.step(a_times, a_muts, color=ADAPTIVE_COLOR, linewidth=2,
            label='Adaptive MTD', where='post')
    ax.step(b_times, b_muts, color=BASELINE_COLOR, linewidth=2,
            label='Baseline MTD', where='post', linestyle='--')

    style_ax(ax, "Cumulative Mutations Over Time",
             "Time (seconds)", "Number of Mutations")
    ax.legend(fontsize=10)

    # Add annotation boxes
    a_final = a_muts[-1] if a_muts else 0
    b_final = b_muts[-1] if b_muts else 0
    ax.annotate(f'Total: {a_final}',
                xy=(a_times[-1], a_final),
                xytext=(a_times[-1]-30, a_final+0.3),
                color=ADAPTIVE_COLOR, fontsize=9, fontweight='bold')
    ax.annotate(f'Total: {b_final}',
                xy=(b_times[-1], b_final),
                xytext=(b_times[-1]-30, b_final+0.3),
                color=BASELINE_COLOR, fontsize=9, fontweight='bold')

    plt.tight_layout()
    path = "results/graphs/02_mutations_over_time.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {path}")


# ── Chart 3: Measured Fingerprint Detectability (real classifier) ────────────
def chart_detectability():
    """
    Plots the MEASURED classifier result.

    An earlier version of this chart hardcoded scores of 1000.0 vs 1.6 and
    annotated "Baseline is 613x more detectable". Those numbers came from a
    simulation that invented its own timings, not from any experiment, and a
    real Random Forest trained on captured traffic contradicted them.
    The values below are the measured F1 scores.
    """
    fig, axes = plt.subplots(1, 2, figsize=(11, 5))

    # (a) realistic attacker: all FLOW_MODs, no priority hint
    bars = axes[0].bar(['Baseline\n(simultaneous)', 'Adaptive\n(staggered)'],
                       [0.833, 0.741], color=[BASELINE_COLOR, ADAPTIVE_COLOR],
                       width=0.45, edgecolor='white', linewidth=1.5)
    for bar, v in zip(bars, [0.833, 0.741]):
        axes[0].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.015,
                     f'{v:.3f}', ha='center', fontsize=12, fontweight='bold')
    style_ax(axes[0], "Realistic attacker\n(all FLOW_MODs, detecting installs)",
             "", "Classifier F1  (lower = more resistant)")
    axes[0].set_ylim(0, 1.0)
    axes[0].text(0.5, 0.90, "staggering gives a modest reduction",
                 transform=axes[0].transAxes, ha='center', fontsize=9,
                 color='#555555', style='italic')

    # (b) pinpointing the trigger instant
    bars = axes[1].bar(['Baseline\n(simultaneous)', 'Adaptive\n(staggered)'],
                       [0.958, 0.000], color=[BASELINE_COLOR, ADAPTIVE_COLOR],
                       width=0.45, edgecolor='white', linewidth=1.5)
    for bar, v in zip(bars, [0.958, 0.000]):
        axes[1].text(bar.get_x()+bar.get_width()/2, bar.get_height()+0.015,
                     f'{v:.3f}', ha='center', fontsize=12, fontweight='bold')
    style_ax(axes[1], "Pinpointing the mutation trigger\n(when the mutation fired)",
             "", "Classifier F1  (lower = more resistant)")
    axes[1].set_ylim(0, 1.0)
    axes[1].text(0.5, 0.90, "attacker cannot locate the trigger at all",
                 transform=axes[1].transAxes, ha='center', fontsize=9,
                 color='#555555', style='italic')

    plt.suptitle("Measured Fingerprint Detectability - Random Forest on captured traffic",
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = "results/graphs/03_detectability_measured.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {path}")


# ── Chart 4: Installation Window Spread ──────────────────────────────────────
def chart_installation_window():
    fig, ax = plt.subplots(figsize=(10, 5))

    # Read the MEASURED install windows from the trace rather than inventing
    # them. Falls back to a clear message if the trace is unavailable.
    per = {}
    if os.path.exists("logs/install_trace.log"):
        with open("logs/install_trace.log") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    e = json.loads(line)
                except json.JSONDecodeError:
                    continue
                per.setdefault(e["mutation_id"], []).append(float(e["install_ts"]))
    adaptive_windows = [round(max(v) - min(v), 3) for v in per.values() if len(v) > 1]
    if not adaptive_windows:
        print("[!] No install trace found - skipping installation window chart.")
        return
    mutations = list(range(1, len(adaptive_windows) + 1))
    baseline_windows = [0.0] * len(adaptive_windows)   # simultaneous by definition

    x = [m - 0.15 for m in mutations]
    y = [m + 0.15 for m in mutations]

    ax.bar(x, baseline_windows, width=0.25, color=BASELINE_COLOR,
           label='Baseline MTD', alpha=0.8)
    ax.bar(y, adaptive_windows, width=0.25, color=ADAPTIVE_COLOR,
           label='Adaptive MTD', alpha=0.8)

    style_ax(ax, "Flow Rule Installation Window Per Mutation\n(Width = Time Spread Across Switches)",
             "Mutation Number", "Installation Window (seconds)")
    ax.legend(fontsize=10)
    ax.set_xticks(mutations)

    avg_adaptive = sum(adaptive_windows) / len(adaptive_windows)
    ax.axhline(avg_adaptive, color=ADAPTIVE_COLOR, linestyle=':',
               alpha=0.7, label=f'Adaptive avg ({avg_adaptive:.2f}s)')
    ax.text(len(mutations)+0.2, avg_adaptive, f'{avg_adaptive:.2f}s avg',
            color=ADAPTIVE_COLOR, fontsize=9, va='center')

    plt.tight_layout()
    path = "results/graphs/04_installation_window.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {path}")


# ── Chart 5: Summary Comparison Bar Chart ─────────────────────────────────────
def chart_summary(adaptive, baseline):
    fig, axes = plt.subplots(1, 3, figsize=(13, 5))

    a_cpu  = [r['cpu_pct'] for r in adaptive]
    b_cpu  = [r['cpu_pct'] for r in baseline]
    a_muts = adaptive[-1]['mutations'] if adaptive else 0
    b_muts = baseline[-1]['mutations'] if baseline else 0
    a_thr  = adaptive[-1].get('threat_events', 0) if adaptive else 0
    b_thr  = baseline[-1].get('threat_events', 0) if baseline else 0

    def bar_pair(ax, a_val, b_val, title, ylabel, fmt="{:.2f}"):
        bars = ax.bar(['Adaptive', 'Baseline'], [a_val, b_val],
                      color=[ADAPTIVE_COLOR, BASELINE_COLOR],
                      width=0.4, edgecolor='white')
        for bar, val in zip(bars, [a_val, b_val]):
            ax.text(bar.get_x() + bar.get_width()/2,
                    bar.get_height() + max(a_val, b_val)*0.02,
                    fmt.format(val), ha='center', fontsize=10, fontweight='bold')
        style_ax(ax, title, "", ylabel)

    bar_pair(axes[0], sum(a_cpu)/len(a_cpu) if a_cpu else 0,
             sum(b_cpu)/len(b_cpu) if b_cpu else 0,
             "Average CPU Usage", "CPU (%)", "{:.2f}%")
    bar_pair(axes[1], a_muts, b_muts,
             "Total Mutations", "Count", "{:.0f}")
    bar_pair(axes[2], a_thr, b_thr,
             "Threat Events Detected", "Count", "{:.0f}")

    plt.suptitle("Adaptive vs Baseline MTD — Performance Summary",
                 fontsize=13, fontweight='bold', y=1.02)
    plt.tight_layout()
    path = "results/graphs/05_summary_comparison.png"
    plt.savefig(path, dpi=150, bbox_inches='tight')
    plt.close()
    print(f"[+] Saved: {path}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--adaptive', required=True)
    parser.add_argument('--baseline', required=True)
    args = parser.parse_args()

    print("\n[*] Loading experiment data...")
    adaptive = load_jsonl(args.adaptive)
    baseline = load_jsonl(args.baseline)

    if not adaptive or not baseline:
        print("[!] Could not load data files. Check paths.")
        exit(1)

    print(f"[*] Adaptive: {len(adaptive)} samples")
    print(f"[*] Baseline: {len(baseline)} samples")
    print("[*] Generating charts...\n")

    chart_cpu(adaptive, baseline)
    chart_mutations(adaptive, baseline)
    chart_detectability()
    chart_installation_window()
    chart_summary(adaptive, baseline)

    print("\n[*] All charts saved to results/graphs/")
    print("[*] Copy them to Windows with:")
    print("    scp -P 2222 -r mininet@127.0.0.1:~/mtd_sdn_project/results/graphs/ .")
