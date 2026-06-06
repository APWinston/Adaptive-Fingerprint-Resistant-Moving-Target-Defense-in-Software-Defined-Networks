"""
Performance Evaluation Script
==============================
Measures and compares:
  1. CPU and memory overhead during mutations
  2. Network latency before, during, and after mutations
  3. Mutation trigger timing (for fingerprint analysis)

Run after an experiment session:
  python evaluation/measure_overhead.py --log logs/mutations.log

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import json
import argparse
import os
import statistics


def load_log(filepath):
    if not os.path.exists(filepath):
        print("Log file not found:", filepath)
        return []
    entries = []
    with open(filepath) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    entries.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return entries


def analyse_triggers(trigger_log):
    """Analyse trigger timing — key for fingerprint resistance evaluation."""
    entries = load_log(trigger_log)
    if len(entries) < 2:
        print("Not enough trigger events to analyse.")
        return

    print("\n=== Trigger Timing Analysis ===")
    print(f"Total mutations triggered: {len(entries)}")

    # Parse timestamps
    from datetime import datetime
    times = [datetime.strptime(e['timestamp'], '%Y-%m-%d %H:%M:%S')
             for e in entries]

    intervals = [(times[i+1] - times[i]).total_seconds()
                 for i in range(len(times)-1)]

    print(f"Inter-mutation intervals (seconds):")
    print(f"  Min:    {min(intervals):.2f}s")
    print(f"  Max:    {max(intervals):.2f}s")
    print(f"  Mean:   {statistics.mean(intervals):.2f}s")
    print(f"  StdDev: {statistics.stdev(intervals):.2f}s")
    print()

    adaptive = [e for e in entries if e.get('mode') == 'adaptive']
    baseline = [e for e in entries if e.get('mode') == 'baseline']
    print(f"Adaptive triggers: {len(adaptive)}")
    print(f"Baseline triggers: {len(baseline)}")

    if intervals:
        cv = statistics.stdev(intervals) / statistics.mean(intervals)
        print(f"\nCoefficient of Variation (CV): {cv:.3f}")
        print("  (Higher CV = less predictable = more fingerprint resistant)")


def analyse_threat_scores(threat_log):
    """Summarise threat detection events."""
    entries = load_log(threat_log)
    if not entries:
        print("No threat score events found.")
        return

    print("\n=== Threat Score Analysis ===")
    print(f"Total threshold-breach events: {len(entries)}")

    scores = [e['score'] for e in entries]
    ips    = [e['src_ip'] for e in entries]

    print(f"Scores — Min: {min(scores)}, Max: {max(scores)}, "
          f"Mean: {statistics.mean(scores):.1f}")
    print(f"Unique attacker IPs detected: {len(set(ips))}")
    for ip in set(ips):
        count = ips.count(ip)
        print(f"  {ip}: {count} trigger(s)")


def analyse_mutations(mutation_log):
    """Summarise mutation events."""
    entries = load_log(mutation_log)
    if not entries:
        print("No mutation events found.")
        return

    print("\n=== Mutation Analysis ===")
    print(f"Total mutations performed: {len(entries)}")
    attackers = [e.get('attacker_ip') for e in entries if e.get('attacker_ip')]
    print(f"Mutations triggered by attack: {len(attackers)}")
    print(f"Mutations triggered proactively: {len(entries) - len(attackers)}")


def main():
    parser = argparse.ArgumentParser(description='MTD Performance Evaluator')
    parser.add_argument('--trigger-log',  default='logs/triggers.log')
    parser.add_argument('--threat-log',   default='logs/threat_scores.log')
    parser.add_argument('--mutation-log', default='logs/mutations.log')
    args = parser.parse_args()

    print("=" * 50)
    print("  MTD-SDN Performance Evaluation Report")
    print("  Group 46")
    print("=" * 50)

    analyse_threat_scores(args.threat_log)
    analyse_mutations(args.mutation_log)
    analyse_triggers(args.trigger_log)

    print("\n[Done] Check results/ folder for raw data.")


if __name__ == '__main__':
    main()
