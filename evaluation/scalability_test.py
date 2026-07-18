"""
Scalability Sweep
=================
Measures how the MTD system behaves as the node count grows, rather than
reporting a single ratio at one topology size.

WHY THIS SCRIPT EXISTS
----------------------
The KPI is defined as

    Scalability = Throughput / Number of Nodes

and was previously computed as 94.7 Mbps / 5 nodes = 18.94 Mbps/node.
Two things were wrong with that:

  1. The numerator was ONE iperf flow (h1 -> h3) while the other three
     hosts were idle. Dividing one pair's throughput by the node count
     does not describe what a node gets. Adding five idle hosts would
     have "halved" the metric without changing anything real.

  2. One data point is not a scalability result. Scalability is about the
     TREND as N grows. A single N tells you nothing about the trend.

This script fixes both: it drives N/2 concurrent flows so the numerator is
a true aggregate, and it sweeps N so there is a curve to report.

It also records the thing that actually limits this defence. Each mutation
installs |hosts| x |switches| flow rules, so the install cost grows as
O(N*M). Install window and controller CPU are captured at every N for
exactly that reason.

PREREQUISITE
------------
The controller must already be running in another terminal, e.g.

    ryu-manager controller/mtd_controller.py

Run:

    sudo python3 evaluation/scalability_test.py
    sudo python3 evaluation/scalability_test.py --sizes 4,8,16,32 --duration 10

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import argparse
import json
import os
import re
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.log import setLogLevel, info
from topology.mtd_topo_scale import build_scaled_net, host_pairs

INSTALL_TRACE = "logs/install_trace.log"
CONTROLLER   = "controller/mtd_controller_rhm.py"


def start_controller(mode="adaptive_floor"):
    """
    Launch a fresh ryu for one sweep point and wait for it to be ready.

    The sweep calls `mn -c` between sizes, and mn -c issues a DELAYED
    `pkill -9 ryu-manager` that can land a second or two later - right as
    the next size's controller is booting. That race killed every size
    after the first ("ryu-manager not found", "Unable to contact the
    remote controller").

    Two guards fix it:
      - drain any lingering ryu and free port 6633 BEFORE launching, so
        the new controller starts from a clean slate;
      - a short settle AFTER launch, past the window in which a late pkill
        from the previous mn -c could still arrive.
    """
    import subprocess, time, os, signal

    # Drain any previous controller and wait for the port to actually free.
    subprocess.call("pkill -9 -f ryu-manager > /dev/null 2>&1", shell=True)
    for _ in range(20):
        rc = subprocess.call("ss -ltn 2>/dev/null | grep -q ':6633 '", shell=True)
        if rc != 0:            # grep found nothing -> port is free
            break
        time.sleep(0.5)
    time.sleep(1)              # past any straggling delayed pkill

    env = dict(os.environ, MTD_MODE=mode, PYTHONUNBUFFERED="1")
    logf = open("logs/ryu_scale.log", "w")
    proc = subprocess.Popen(
        ["ryu-manager", CONTROLLER],
        env=env, stdout=logf, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)

    deadline = time.time() + 25
    while time.time() < deadline:
        if proc.poll() is not None:
            return None        # exited during boot (usually port clash)
        try:
            with open("logs/ryu_scale.log") as f:
                if "Controller started" in f.read():
                    time.sleep(1)   # let it finish wiring the OF handler
                    return proc
        except IOError:
            pass
        time.sleep(0.5)
    return proc


def stop_controller(proc):
    import os, signal, time
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        proc.wait(timeout=5)
    except Exception:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
        except Exception:
            pass
MAPPING_FILE  = "logs/current_mapping.json"
RESULTS_DIR   = "results"


# ---------------------------------------------------------------- address resolution
def load_mapping(timeout=15):
    """
    Read the controller's live real -> virtual mapping.

    Required because the RHM pipeline shields real addresses: iperf aimed
    at srv.IP() is dropped at the switch and every measurement reads 0.
    Traffic must be addressed to the virtual address, exactly as an ARP
    proxy would hand it out.

    Polls, because registration happens as the warm-up ARPs arrive and the
    file will not exist for the first moment or two.
    """
    deadline = time.time() + timeout
    while time.time() < deadline:
        if os.path.exists(MAPPING_FILE):
            try:
                with open(MAPPING_FILE) as f:
                    return json.load(f).get("mapping", {})
            except (IOError, ValueError):
                pass
        time.sleep(0.5)
    return {}


def target_of(host, mapping):
    """
    Virtual address for a host, or its real address if the controller is
    the legacy one with no shield.

    Returning the real address as a fallback keeps this script usable
    against mtd_controller.py, where real addresses still work and no
    mapping file is produced.
    """
    return mapping.get(host.IP(), host.IP())


# ---------------------------------------------------------------- controller CPU
def find_ryu_pid():
    """PID of the running ryu-manager, or None."""
    try:
        out = subprocess.check_output(["pgrep", "-f", "ryu-manager"],
                                      stderr=subprocess.DEVNULL).decode()
        pids = [int(p) for p in out.split()]
        return pids[0] if pids else None
    except (subprocess.CalledProcessError, ValueError):
        return None


def read_cpu_jiffies(pid):
    """Total CPU jiffies (utime+stime) consumed by pid so far."""
    try:
        with open("/proc/%d/stat" % pid) as f:
            parts = f.read().split()
        # fields 14 and 15 (1-indexed) are utime and stime
        return int(parts[13]) + int(parts[14])
    except (IOError, IndexError, ValueError):
        return None


def cpu_percent_over(pid, seconds):
    """
    Mean CPU% of pid over a window, measured from /proc rather than by
    sampling psutil, so no extra dependency is needed inside the VM.
    """
    if pid is None:
        return None
    hz = os.sysconf("SC_CLK_TCK")
    a = read_cpu_jiffies(pid)
    if a is None:
        return None
    time.sleep(seconds)
    b = read_cpu_jiffies(pid)
    if b is None:
        return None
    return round(100.0 * (b - a) / hz / seconds, 3)


# ---------------------------------------------------------------- install trace
def trace_snapshot():
    """Number of lines currently in the install trace."""
    if not os.path.exists(INSTALL_TRACE):
        return 0
    with open(INSTALL_TRACE) as f:
        return sum(1 for line in f if line.strip())


def trace_since(offset):
    """Install trace entries appended after `offset` lines."""
    if not os.path.exists(INSTALL_TRACE):
        return []
    out = []
    with open(INSTALL_TRACE) as f:
        for i, line in enumerate(f):
            if i < offset or not line.strip():
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return out


def install_window_of(entries):
    """
    Mean spread between first and last switch install per mutation.

    Grouped by (mode, mutation_id) rather than mutation_id alone. Grouping
    on the id by itself merges an adaptive mutation #1 with a baseline
    mutation #1 if both runs ever land in one trace file, which turns the
    spread into the gap between two runs - hundreds of seconds instead of
    ~1s.
    """
    per = {}
    for e in entries:
        key = (e.get("mode", "?"), e.get("mutation_id"))
        per.setdefault(key, []).append(float(e["install_ts"]))
    windows = [max(v) - min(v) for v in per.values() if len(v) > 1]
    if not windows:
        return None, 0
    return round(sum(windows) / len(windows), 4), len(windows)


def rules_per_mutation(entries):
    """Mean switch-installs per mutation = how many rule pushes each mutation costs."""
    per = {}
    for e in entries:
        key = (e.get("mode", "?"), e.get("mutation_id"))
        per[key] = per.get(key, 0) + 1
    if not per:
        return None
    return round(sum(per.values()) / len(per), 2)


# ---------------------------------------------------------------- iperf
def parse_iperf_csv(out):
    """
    Extract Mbit/s from `iperf -y c` output. The final field of the last
    complete line is bits/sec.
    """
    best = None
    for line in out.strip().splitlines():
        fields = line.strip().split(",")
        if len(fields) >= 9:
            try:
                best = float(fields[8]) / 1e6
            except ValueError:
                continue
    return round(best, 2) if best is not None else None


def run_size(n_hosts, n_switches, duration, warmup_scan, edge_bw, core_bw):
    """Run one point of the sweep. Returns a result dict."""
    info("\n*** === N = %d hosts, %d switches ===\n" % (n_hosts, n_switches))

    # Each size gets its own controller. mn -c between sizes kills the
    # previous one, so relying on a single external ryu leaves every size
    # after the first with no controller at all.
    ctrl = start_controller()
    if ctrl is None:
        info("*** N=%d FAILED: controller would not start (see logs/ryu_scale.log)\n" % n_hosts)
        return None
    time.sleep(1)

    try:
        net, hosts, attacker, switches = build_scaled_net(
            n_hosts=n_hosts, n_switches=n_switches,
            edge_bw=edge_bw, core_bw=core_bw)
        net.start()
    except Exception as exc:
        stop_controller(ctrl)
        info("*** N=%d FAILED during build: %s\n" % (n_hosts, exc))
        return None
    time.sleep(3)

    # Warm-up: the controller only registers a host for mutation once it
    # has seen traffic from it. Without this the mapping is empty, every
    # mutation is a no-op, and the install cost we are trying to measure
    # never happens.
    # Under the RHM pipeline every one of these pings FAILS - real
    # addresses are shielded. That is expected and is not a problem: the
    # ARP exchange each ping triggers is what registers the host with the
    # controller, and registration is all the warm-up is for.
    info("*** Warm-up pingAll to register hosts (pings will fail under RHM; ARP is the point)\n")
    net.pingAll(timeout='1')

    mapping = load_mapping()
    if mapping:
        info("*** Resolved %d virtual addresses from the controller\n" % len(mapping))
    else:
        info("*** No mapping file; assuming legacy controller and using real addresses\n")

    trace_offset = trace_snapshot()
    ryu_pid = find_ryu_pid()
    if ryu_pid is None:
        info("*** WARNING: ryu-manager not found; CPU will be reported as N/A\n")

    # Optional scan so the adaptive controller actually triggers mutations
    # during the throughput measurement, rather than sitting idle. Without
    # it, an adaptive run measures throughput on a network that is never
    # mutating, which is not the condition we want to characterise.
    if warmup_scan:
        info("*** Starting background scan to drive mutations\n")
        target = hosts[0].IP()
        attacker.cmd('(nmap -sS -p 1-1000 --host-timeout 60s %s > /dev/null 2>&1 &)'
                     % target)
        time.sleep(2)

    # -- concurrent iperf across N/2 pairs --------------------------------
    pairs = host_pairs(hosts, n_switches)
    info("*** Starting %d concurrent iperf pairs for %ds\n" % (len(pairs), duration))

    for _, srv in pairs:
        srv.cmd('iperf -s -D > /dev/null 2>&1')
    time.sleep(1)

    for cli, srv in pairs:
        cli.sendCmd('iperf -c %s -t %d -y c' % (target_of(srv, mapping), duration))

    # Measure controller CPU while the flows are actually running.
    cpu = cpu_percent_over(ryu_pid, min(duration, 8)) if ryu_pid else None

    throughputs = []
    for cli, _ in pairs:
        out = cli.waitOutput()
        mbps = parse_iperf_csv(out)
        if mbps is not None:
            throughputs.append(mbps)

    for _, srv in pairs:
        srv.cmd('kill %iperf 2>/dev/null')

    entries = trace_since(trace_offset)
    win, win_n = install_window_of(entries)
    rpm = rules_per_mutation(entries)

    net.stop()
    stop_controller(ctrl)

    aggregate = round(sum(throughputs), 2) if throughputs else None
    per_node  = round(aggregate / n_hosts, 3) if aggregate else None

    result = {
        "n_hosts":            n_hosts,
        "n_switches":         n_switches,
        "n_pairs":            len(pairs),
        "flows_measured":     len(throughputs),
        "aggregate_mbps":     aggregate,
        "per_node_mbps":      per_node,
        "mean_flow_mbps":     round(sum(throughputs) / len(throughputs), 2) if throughputs else None,
        "install_window_s":   win,
        "mutations_observed": win_n,
        "installs_per_mut":   rpm,
        "expected_rules_per_mut": n_hosts * n_switches,
        "controller_cpu_pct": cpu,
    }
    info("*** N=%d: aggregate=%s Mbps  per-node=%s Mbps  cpu=%s%%  window=%ss\n"
         % (n_hosts, aggregate, per_node, cpu, win))
    return result


def main():
    ap = argparse.ArgumentParser(description="MTD scalability sweep (Group 46)")
    ap.add_argument("--sizes", default="4,8,16,32",
                    help="comma-separated host counts to sweep")
    ap.add_argument("--switches", type=int, default=2)
    ap.add_argument("--duration", type=int, default=10,
                    help="iperf duration per size, seconds")
    ap.add_argument("--edge-bw", type=float, default=100)
    ap.add_argument("--core-bw", type=float, default=1000)
    ap.add_argument("--no-scan", action="store_true",
                    help="do not drive mutations during the measurement")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    setLogLevel('info')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    sizes = [int(s) for s in args.sizes.split(",") if s.strip()]
    out_path = args.out or os.path.join(
        RESULTS_DIR, "scalability_%s.jsonl" % time.strftime("%Y%m%d_%H%M%S"))

    results = []
    for n in sizes:
        if n < 2:
            info("*** skipping N=%d (need at least one pair)\n" % n)
            continue
        try:
            r = run_size(n, args.switches, args.duration,
                         not args.no_scan, args.edge_bw, args.core_bw)
            results.append(r)
            with open(out_path, "a") as f:
                f.write(json.dumps(r) + "\n")
        except Exception as exc:
            info("*** N=%d FAILED: %s\n" % (n, exc))
        # net.stop() + stop_controller already ran inside run_size. The
        # per-size start_controller drains any straggler and waits for the
        # port, so no mn -c is needed here - and mn -c's delayed pkill is
        # exactly what used to kill the next size's controller.
        time.sleep(1)

    # -- report -----------------------------------------------------------
    line = "=" * 78
    print("\n" + line)
    print("  MTD SCALABILITY SWEEP  -  Group 46")
    print(line)
    print("%-8s%-12s%-14s%-12s%-14s%-10s" %
          ("N", "aggregate", "per-node", "CPU %", "install win", "installs"))
    print("%-8s%-12s%-14s%-12s%-14s%-10s" %
          ("", "(Mbps)", "(Mbps/node)", "", "(s)", "/mutation"))
    print("-" * 78)
    for r in results:
        print("%-8s%-12s%-14s%-12s%-14s%-10s" % (
            r["n_hosts"],
            r["aggregate_mbps"], r["per_node_mbps"],
            r["controller_cpu_pct"], r["install_window_s"],
            r["installs_per_mut"]))
    print("-" * 78)
    print("\nSaved: %s" % out_path)
    print("\nREADING THIS TABLE")
    print("-" * 78)
    print("  per-node Mbps is the KPI (aggregate / N). A flat line means the")
    print("  defence does not degrade the data plane as the network grows; a")
    print("  falling line means it does, and where it starts falling is the")
    print("  scalability limit worth reporting.")
    print("")
    print("  installs/mutation should track N x switches. That is the cost")
    print("  that grows with the network, and it is what pushes the install")
    print("  window and controller CPU up as N increases.")
    print("")
    print("  Note: per-node Mbps also falls once the core link saturates,")
    print("  which is a property of the topology, not of the MTD. Compare")
    print("  against a --no-scan run to separate the two.")


if __name__ == '__main__':
    main()
