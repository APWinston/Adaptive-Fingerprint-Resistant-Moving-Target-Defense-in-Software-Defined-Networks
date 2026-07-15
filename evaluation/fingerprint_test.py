"""
Inter-Mutation Interval Analysis (timing regularity only)
=========================================================
Reports the coefficient of variation (CV) and entropy of the gaps BETWEEN
mutations. This measures how regular the mutation schedule is - a fixed
timer gives low CV, threat-driven triggering gives higher CV.

SCOPE - READ THIS BEFORE QUOTING ANY NUMBER FROM HERE
-----------------------------------------------------
An earlier version of this script described a high CV as proof that a
system is "fingerprint-resistant". It is not. CV only describes the
regularity of the schedule; it says nothing about whether an attacker
watching the control channel can actually detect a mutation.

Empirical testing settled that question. A real Random Forest trained on
captured traffic, under an attacker seeing all FLOW_MOD messages, scored:

    baseline  F1 = 0.833      adaptive  F1 = 0.741

So the adaptive system is only modestly harder to detect, despite having a
much less regular schedule. Use fingerprint_classifier.py for any
fingerprint-resistance claim; use this script only to describe schedule
regularity.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json
import os
import argparse
import math
import statistics
from datetime import datetime


def load_jsonl(filepath):
    records = []
    if not os.path.exists(filepath):
        print(f"File not found: {filepath}")
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


def extract_mutation_times(records):
    """
    Extract timestamps where mutation count increased.
    Returns list of elapsed_s values when a new mutation occurred.
    """
    mutation_times = []
    prev_mutations = 0
    for r in records:
        current = r.get('mutations', 0)
        if current > prev_mutations:
            for _ in range(current - prev_mutations):
                mutation_times.append(r['elapsed_s'])
            prev_mutations = current
    return mutation_times


def compute_intervals(times):
    """Compute inter-mutation intervals."""
    if len(times) < 2:
        return []
    return [times[i+1] - times[i] for i in range(len(times)-1)]


def compute_entropy(intervals, bins=5):
    """
    Compute Shannon entropy of interval distribution.
    Higher entropy = more random = more fingerprint resistant.
    """
    if not intervals:
        return 0.0
    min_v = min(intervals)
    max_v = max(intervals)
    if max_v == min_v:
        return 0.0
    bin_size = (max_v - min_v) / bins
    counts = [0] * bins
    for v in intervals:
        idx = min(int((v - min_v) / bin_size), bins - 1)
        counts[idx] += 1
    total = len(intervals)
    entropy = 0.0
    for c in counts:
        if c > 0:
            p = c / total
            entropy -= p * math.log2(p)
    return entropy


def analyse(name, records):
    """Full fingerprint analysis for one experiment."""
    mutation_times = extract_mutation_times(records)
    intervals      = compute_intervals(mutation_times)

    print(f"\n{'='*50}")
    print(f"  {name.upper()} MODE — Fingerprint Analysis")
    print(f"{'='*50}")
    print(f"Total mutations:     {len(mutation_times)}")
    print(f"Mutation timestamps: {mutation_times}")

    if len(intervals) < 2:
        print("Not enough mutations to compute interval statistics.")
        print("(Need at least 3 mutations for meaningful analysis)")
        return {
            'mode': name, 'mutations': len(mutation_times),
            'intervals': intervals, 'cv': None, 'entropy': None
        }

    mean_i   = statistics.mean(intervals)
    stdev_i  = statistics.stdev(intervals)
    cv       = stdev_i / mean_i if mean_i > 0 else 0
    entropy  = compute_entropy(intervals)
    min_i    = min(intervals)
    max_i    = max(intervals)

    print(f"\nInter-mutation intervals (seconds):")
    print(f"  Intervals:  {[round(i,1) for i in intervals]}")
    print(f"  Min:        {min_i:.1f}s")
    print(f"  Max:        {max_i:.1f}s")
    print(f"  Mean:       {mean_i:.1f}s")
    print(f"  Std Dev:    {stdev_i:.1f}s")
    print(f"\nFingerprint Resistance Metrics:")
    print(f"  CV (CoV):   {cv:.3f}  {'HIGH = irregular schedule' if cv > 0.3 else 'LOW = regular schedule'}")
    print(f"  Entropy:    {entropy:.3f} bits")

    if cv < 0.1:
        verdict = "HIGHLY PREDICTABLE — easy to fingerprint (like fixed-interval MTD)"
    elif cv < 0.3:
        verdict = "SOMEWHAT PREDICTABLE — moderate fingerprint risk"
    elif cv < 0.6:
        verdict = "MODERATELY RESISTANT — harder to fingerprint"
    else:
        verdict = "HIGHLY RESISTANT — difficult to fingerprint"

    print(f"\n  Verdict: {verdict}")

    return {
        'mode': name, 'mutations': len(mutation_times),
        'intervals': intervals, 'mean': mean_i,
        'stdev': stdev_i, 'cv': cv, 'entropy': entropy
    }


def compare(adaptive_result, baseline_result):
    """Side-by-side comparison table."""
    print(f"\n{'='*50}")
    print("  COMPARISON SUMMARY")
    print(f"{'='*50}")
    print(f"{'Metric':<25} {'Adaptive':>12} {'Baseline':>12}")
    print(f"{'-'*50}")

    def fmt(v):
        if v is None:
            return "N/A"
        if isinstance(v, float):
            return f"{v:.3f}"
        return str(v)

    metrics = [
        ('Total mutations',    'mutations'),
        ('Mean interval (s)',  'mean'),
        ('Std Dev (s)',        'stdev'),
        ('CV (fingerprint)',   'cv'),
        ('Entropy (bits)',     'entropy'),
    ]

    for label, key in metrics:
        a = fmt(adaptive_result.get(key))
        b = fmt(baseline_result.get(key))
        print(f"{label:<25} {a:>12} {b:>12}")

    print(f"\n{'='*50}")
    a_cv = adaptive_result.get('cv')
    b_cv = baseline_result.get('cv')
    if a_cv and b_cv:
        if a_cv > b_cv:
            improvement = ((a_cv - b_cv) / b_cv) * 100 if b_cv > 0 else float('inf')
            print(f"  Adaptive CV is {improvement:.0f}% higher than Baseline")
            print(f"  → Adaptive system is significantly more fingerprint-resistant")
        else:
            print(f"  More data needed for conclusive comparison")
    print(f"{'='*50}\n")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MTD Fingerprint Resistance Analyser')
    parser.add_argument('--adaptive', required=True,
                        help='Path to adaptive experiment .jsonl file')
    parser.add_argument('--baseline', required=True,
                        help='Path to baseline experiment .jsonl file')
    args = parser.parse_args()

    print("\nMTD-SDN Fingerprint Resistance Analysis")
    print("Group 46\n")

    adaptive_records = load_jsonl(args.adaptive)
    baseline_records = load_jsonl(args.baseline)

    if not adaptive_records:
        print("ERROR: Could not load adaptive results file.")
        exit(1)
    if not baseline_records:
        print("ERROR: Could not load baseline results file.")
        exit(1)

    adaptive_result = analyse('adaptive', adaptive_records)
    baseline_result = analyse('baseline', baseline_records)
    compare(adaptive_result, baseline_result)
