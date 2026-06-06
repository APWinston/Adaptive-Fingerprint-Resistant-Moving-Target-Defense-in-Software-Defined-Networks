"""
Experiment Data Collector
==========================
Records timestamped metrics during a live experiment run.
Run this in a third SSH window while the controller and
topology are running.

Usage:
  python evaluation/collect_data.py --mode adaptive --duration 120
  python evaluation/collect_data.py --mode baseline --duration 120

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import time
import argparse
import json
import os
import subprocess

os.makedirs("results", exist_ok=True)
os.makedirs("logs", exist_ok=True)


def get_cpu_memory():
    """Get current CPU and memory usage of ryu-manager process."""
    try:
        result = subprocess.run(
            ["ps", "aux"],
            capture_output=True, text=True
        )
        for line in result.stdout.splitlines():
            if "ryu-manager" in line:
                parts = line.split()
                cpu = float(parts[2])
                mem = float(parts[3])
                return cpu, mem
    except Exception:
        pass
    return 0.0, 0.0


def count_log_entries(logfile):
    """Count entries in a log file."""
    if not os.path.exists(logfile):
        return 0
    with open(logfile) as f:
        return sum(1 for line in f if line.strip())


def collect(mode, duration, interval=5):
    """
    Collect metrics every `interval` seconds for `duration` seconds.
    """
    output_file = f"results/experiment_{mode}_{int(time.time())}.jsonl"
    print(f"[*] Collecting data for {duration}s in {mode.upper()} mode")
    print(f"[*] Output: {output_file}")
    print(f"[*] Sampling every {interval}s")
    print("[*] Press Ctrl+C to stop early\n")

    start_time = time.time()
    sample_num = 0

    try:
        while time.time() - start_time < duration:
            elapsed = time.time() - start_time
            cpu, mem = get_cpu_memory()
            mutations  = count_log_entries("logs/mutations.log")
            triggers   = count_log_entries("logs/triggers.log")
            threats    = count_log_entries("logs/threat_scores.log")

            record = {
                "sample":       sample_num,
                "elapsed_s":    round(elapsed, 1),
                "mode":         mode,
                "cpu_pct":      cpu,
                "mem_pct":      mem,
                "mutations":    mutations,
                "triggers":     triggers,
                "threat_events": threats,
                "timestamp":    time.strftime('%Y-%m-%d %H:%M:%S')
            }

            with open(output_file, 'a') as f:
                f.write(json.dumps(record) + '\n')

            print(f"  t={elapsed:6.1f}s | CPU={cpu:.1f}% | MEM={mem:.1f}% | "
                  f"mutations={mutations} | triggers={triggers}")

            sample_num += 1
            time.sleep(interval)

    except KeyboardInterrupt:
        print("\n[*] Collection stopped by user")

    print(f"\n[*] Done. {sample_num} samples saved to {output_file}")
    return output_file


def summarise(filepath):
    """Print a quick summary of collected data."""
    if not os.path.exists(filepath):
        print("File not found:", filepath)
        return

    records = []
    with open(filepath) as f:
        for line in f:
            if line.strip():
                records.append(json.loads(line))

    if not records:
        print("No data found.")
        return

    cpus = [r['cpu_pct'] for r in records]
    mems = [r['mem_pct'] for r in records]
    last = records[-1]

    print("\n=== Experiment Summary ===")
    print(f"Mode:            {last['mode'].upper()}")
    print(f"Duration:        {last['elapsed_s']}s")
    print(f"Samples:         {len(records)}")
    print(f"Avg CPU:         {sum(cpus)/len(cpus):.2f}%")
    print(f"Max CPU:         {max(cpus):.2f}%")
    print(f"Avg Memory:      {sum(mems)/len(mems):.2f}%")
    print(f"Total mutations: {last['mutations']}")
    print(f"Total triggers:  {last['triggers']}")
    print(f"Threat events:   {last['threat_events']}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MTD Experiment Data Collector')
    parser.add_argument('--mode',     choices=['adaptive', 'baseline'],
                        required=True)
    parser.add_argument('--duration', type=int, default=120,
                        help='Collection duration in seconds (default: 120)')
    parser.add_argument('--interval', type=int, default=5,
                        help='Sampling interval in seconds (default: 5)')
    args = parser.parse_args()

    output = collect(args.mode, args.duration, args.interval)
    summarise(output)
