"""
One-Shot Experiment Runner
==========================
Runs ONE complete arm of the experiment - clean, controller, capture,
topology, warm-up, attack, teardown, save, summary - as a single command.

WHY THIS EXISTS
---------------
The manual procedure needed three terminals, two of which block, started
in a fixed order, with a warm-up step that had to be remembered and a
mapping check that had to be eyeballed. Every run had about ten places to
go wrong, and when one did the symptom was almost always the same: silence.
A dead controller, an unregistered host and a genuinely broken pipeline all
present as "everything drops", so a failure told you nothing about its own
cause. Three consecutive runs were lost that way - one to a missing
pingall, one to a controller that was not running, one to an attack aimed
at an address space with nothing in it.

Every one of those is now a named, checked stage that fails loudly and
immediately. A run either produces results or tells you which stage broke
and what to do about it. Nothing is left to remember or to sequence by
hand.

USAGE
-----
    sudo python3 evaluation/run_arm.py --mode adaptive_floor
    sudo python3 evaluation/run_arm.py --mode adaptive
    sudo python3 evaluation/run_arm.py --mode baseline

    sudo python3 evaluation/run_arm.py --mode adaptive_floor --duration 350

Produces, per arm:
    results/install_trace_main_<mode>.log
    results/mutations_main_<mode>.log
    results/capture_<mode>_<ts>.pcap
    results/ryu_<mode>_<ts>.log
    results/summary_<mode>_<ts>.json

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import argparse
import json
import os
import shutil
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PROJECT   = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RESULTS   = os.path.join(PROJECT, "results")
LOGS      = os.path.join(PROJECT, "logs")
MAPPING   = os.path.join(LOGS, "logs_placeholder")   # set properly below
MAPPING   = os.path.join(LOGS, "current_mapping.json")
TRACE     = os.path.join(LOGS, "install_trace.log")
MUTATIONS = os.path.join(LOGS, "mutations.log")
TRIGGERS  = os.path.join(LOGS, "triggers.log")

TOTAL_STAGES = 10
_procs = {"ryu": None, "tcpdump": None, "net": None}


# ----------------------------------------------------------------- plumbing
def stage(n, msg):
    print("[%d/%d] %-46s " % (n, TOTAL_STAGES, msg), end="", flush=True)


def ok(extra=""):
    print("OK" + (("  (%s)" % extra) if extra else ""))


def die(msg, hint=None):
    print("FAIL")
    print("\n  PROBLEM: %s" % msg)
    if hint:
        for line in hint.strip().splitlines():
            print("  %s" % line.strip())
    print("")
    teardown()
    sys.exit(1)


def teardown():
    """Always leave the machine in a runnable state, whatever happened."""
    if _procs["net"]:
        try:
            _procs["net"].stop()
        except Exception:
            pass
        _procs["net"] = None
    for name in ("tcpdump", "ryu"):
        p = _procs[name]
        if p and p.poll() is None:
            try:
                os.killpg(os.getpgid(p.pid), signal.SIGTERM)
                p.wait(timeout=5)
            except Exception:
                try:
                    os.killpg(os.getpgid(p.pid), signal.SIGKILL)
                except Exception:
                    pass
        _procs[name] = None
    subprocess.call("mn -c > /dev/null 2>&1", shell=True)


def read_json(path):
    try:
        with open(path) as f:
            return json.load(f)
    except Exception:
        return None


def load_jsonl(path):
    out = []
    if not os.path.exists(path):
        return out
    with open(path) as f:
        for line in f:
            line = line.strip()
            if line:
                try:
                    out.append(json.loads(line))
                except json.JSONDecodeError:
                    pass
    return out


# ----------------------------------------------------------------- stages
def s1_preflight(mode):
    stage(1, "Preflight checks")
    if os.geteuid() != 0:
        die("Not running as root.", "Mininet needs root. Use: sudo python3 evaluation/run_arm.py ...")
    for tool in ("nmap", "tcpdump", "ryu-manager", "ovs-vsctl"):
        if shutil.which(tool) is None:
            die("'%s' not found on PATH." % tool,
                "Install it, or check you are inside the VM rather than on the Windows host.")
    needed = [
        os.path.join(PROJECT, "controller", "mtd_controller_rhm.py"),
        os.path.join(PROJECT, "controller", "mutation_module_rhm.py"),
        os.path.join(PROJECT, "controller", "mtd_trigger.py"),
    ]
    for f in needed:
        if not os.path.exists(f):
            die("Missing %s" % f, "The scp did not land. Re-copy from Windows.")
    src = open(os.path.join(PROJECT, "controller", "mutation_module_rhm.py")).read()
    if "_is_edge_for" not in src:
        die("mutation_module_rhm.py is the OLD copy (no edge-only translation).",
            "Cross-switch paths will break. Re-copy the current file from Windows.")
    if mode == "adaptive_floor":
        t = open(os.path.join(PROJECT, "controller", "mtd_trigger.py")).read()
        if "IDLE_FLOOR_MIN" not in t:
            die("mtd_trigger.py has no idle floor, but --mode adaptive_floor was requested.",
                "Re-copy mtd_trigger.py from Windows.")
    os.makedirs(RESULTS, exist_ok=True)
    os.makedirs(LOGS, exist_ok=True)
    ok()


def s2_clean():
    stage(2, "Cleaning stale mininet + logs")
    subprocess.call("mn -c > /dev/null 2>&1", shell=True)
    subprocess.call("pkill -f ryu-manager > /dev/null 2>&1", shell=True)
    subprocess.call("pkill -f 'tcpdump -i any' > /dev/null 2>&1", shell=True)
    time.sleep(1)
    # Truncate rather than delete: a fresh file per run is what keeps two
    # runs' mutation_ids from colliding in one trace.
    for f in (TRACE, MUTATIONS, TRIGGERS,
              os.path.join(LOGS, "threat_scores.log")):
        open(f, "w").close()
    if os.path.exists(MAPPING):
        os.remove(MAPPING)
    ok()


def s3_start_ryu(mode, stamp):
    stage(3, "Starting controller (%s)" % mode)
    log_path = os.path.join(RESULTS, "ryu_%s_%s.log" % (mode, stamp))
    env = dict(os.environ, MTD_MODE=mode, PYTHONUNBUFFERED="1")
    lf = open(log_path, "w")
    p = subprocess.Popen(
        ["ryu-manager", "controller/mtd_controller_rhm.py"],
        cwd=PROJECT, env=env, stdout=lf, stderr=subprocess.STDOUT,
        preexec_fn=os.setsid)
    _procs["ryu"] = p

    # Wait for the controller to actually announce itself. Starting the
    # topology against a controller that has not finished booting is how a
    # run ends up 100% dropped with no clue why.
    deadline = time.time() + 25
    while time.time() < deadline:
        if p.poll() is not None:
            die("Controller exited immediately.",
                "Traceback is in %s\n  Last lines:\n%s"
                % (log_path, _tail(log_path, 15)))
        if "Controller started" in _read(log_path):
            ok(os.path.basename(log_path))
            return log_path
        time.sleep(0.5)
    die("Controller did not report 'Controller started' within 25s.",
        "See %s" % log_path)


def s4_start_capture(mode, stamp):
    stage(4, "Starting packet capture")
    out = os.path.join(RESULTS, "capture_%s_%s.pcap" % (mode, stamp))
    # Same filter as scripts/capture_traffic.sh, so the pcaps stay
    # comparable with the ones already captured.
    filt = ("(tcp port 6633) or (tcp port 6653) or (ip proto 1) or "
            "(tcp[tcpflags] & tcp-syn != 0)")
    p = subprocess.Popen(["tcpdump", "-i", "any", "-w", out, filt],
                         stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                         preexec_fn=os.setsid)
    _procs["tcpdump"] = p
    time.sleep(2)
    if p.poll() is not None:
        die("tcpdump exited immediately.", "Try running it by hand to see the error.")
    ok(os.path.basename(out))
    return out


def s5_topology():
    stage(5, "Building topology (5 hosts, 2 switches)")
    from mininet.net import Mininet
    from mininet.node import RemoteController, OVSSwitch
    from mininet.link import TCLink
    from mininet.log import setLogLevel
    setLogLevel("critical")          # our stage output is the UI, not mininet's

    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController, ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')
    attacker = net.addHost('attacker', ip='10.0.0.99/24', mac='00:00:00:00:00:99')
    hosts = [net.addHost('h%d' % i, ip='10.0.0.%d/24' % i,
                         mac='00:00:00:00:00:0%d' % i) for i in range(1, 5)]
    for h in (attacker, hosts[0], hosts[1]):
        net.addLink(h, s1, bw=100, delay='2ms')
    for h in (hosts[2], hosts[3]):
        net.addLink(h, s2, bw=100, delay='2ms')
    net.addLink(s1, s2, bw=1000, delay='1ms')
    net.start()
    _procs["net"] = net
    time.sleep(3)
    ok()
    return net, attacker, hosts


def s6_warmup(net, ryu_log):
    stage(6, "Warm-up: registering hosts")
    # These pings FAIL by design - real addresses are shielded. The ARP each
    # one triggers is the only thing that matters here, because that is what
    # the controller registers hosts from. Forgetting this step is what made
    # an earlier attack sweep an empty address space for 34 rounds.
    net.pingAll(timeout='1')
    time.sleep(2)
    n = _read(ryu_log).count("Host registered:")
    if n == 0:
        die("No hosts registered.",
            "The controller saw no ARP. Check %s for a traceback." % ryu_log)
    ok("%d hosts" % n)


def s7_verify_mapping():
    stage(7, "Verifying virtual address mapping")
    deadline = time.time() + 10
    data = None
    while time.time() < deadline:
        data = read_json(MAPPING)
        if data and len(data.get("mapping", {})) >= 4:
            break
        time.sleep(0.5)
    if not data:
        die("No %s produced." % MAPPING,
            "The controller never registered a host, so there is nothing to attack.")
    m = data.get("mapping", {})
    if len(m) < 4:
        die("Only %d of 4 hosts have virtual addresses: %s" % (len(m), m),
            "Warm-up did not reach every host. Re-run.")
    ok(", ".join("%s->%s" % (k.split('.')[-1], v.split('.')[-1]) for k, v in sorted(m.items())))
    return m


def s8_attack(attacker, duration):
    stage(8, "Running attack (%ds)" % duration)
    script = os.path.join(PROJECT, "scripts", "run_attack_rhm.sh")
    if not os.path.exists(script):
        die("Missing scripts/run_attack_rhm.sh",
            "Copy it from Windows. The old run_attack.sh targets a REAL address,\n"
            "which the shield drops before the threat engine ever sees it.")
    print("")
    print("       (attacker sweeping the virtual pool; ~%d min)" % max(1, duration // 60))
    attacker.cmd('bash %s %d > %s 2>&1' %
                 (script, duration, os.path.join(RESULTS, "attack_out.log")))
    stage(8, "Attack complete")
    ok()


def s9_teardown_and_save(mode, pcap):
    stage(9, "Teardown + saving artifacts")
    if _procs["net"]:
        _procs["net"].stop()
        _procs["net"] = None
    time.sleep(1)
    for name in ("tcpdump", "ryu"):
        p = _procs[name]
        if p and p.poll() is None:
            os.killpg(os.getpgid(p.pid), signal.SIGTERM)
            try:
                p.wait(timeout=5)
            except Exception:
                os.killpg(os.getpgid(p.pid), signal.SIGKILL)
        _procs[name] = None
    time.sleep(1)

    saved = {}
    for src, dst in ((TRACE, "install_trace_main_%s.log" % mode),
                     (MUTATIONS, "mutations_main_%s.log" % mode),
                     (TRIGGERS, "triggers_main_%s.log" % mode)):
        if os.path.exists(src):
            shutil.copy(src, os.path.join(RESULTS, dst))
            saved[dst] = os.path.getsize(src)
    ok("%d files" % len(saved))
    return saved


def s10_summary(mode, stamp, pcap):
    stage(10, "Summary")
    print("")
    muts = load_jsonl(os.path.join(RESULTS, "mutations_main_%s.log" % mode))
    trace = load_jsonl(os.path.join(RESULTS, "install_trace_main_%s.log" % mode))
    trigs = load_jsonl(os.path.join(RESULTS, "triggers_main_%s.log" % mode))

    ts = sorted(m["wall_ts"] for m in muts if "wall_ts" in m)
    gaps = [round(ts[i + 1] - ts[i], 1) for i in range(len(ts) - 1)]
    idle = sum(1 for t in trigs if t.get("mode") == "adaptive_floor_idle")
    threat = len(trigs) - idle

    W = "=" * 68
    print(W)
    print("  ARM COMPLETE: %s" % mode.upper())
    print(W)
    print("  mutations           : %d" % len(muts))
    print("  install trace lines : %d" % len(trace))
    print("  triggers            : %d threat-driven, %d idle-floor" % (threat, idle))
    if ts:
        print("  run span            : %.1fs" % (ts[-1] - ts[0]))
    print("  inter-mutation gaps : %s" % gaps)
    print("  pcap                : %s" % os.path.basename(pcap))
    print(W)

    # The checks that decide whether this arm is usable at all.
    problems = []
    if len(muts) < 3:
        problems.append("Only %d mutations - too few for entropy or fingerprinting." % len(muts))
    if mode.startswith("adaptive") and threat == 0:
        problems.append("ZERO threat-driven triggers. The threat engine never fired,\n"
                        "     so this is not testing adaptive triggering.")
    if mode == "adaptive_floor" and idle == 0:
        problems.append("No idle-floor triggers - the floor never engaged.")
    if problems:
        print("\n  WARNINGS - this arm may not be usable:")
        for p in problems:
            print("   !  %s" % p)
    else:
        print("\n  Looks healthy.")
    print("")

    summary = {
        "mode": mode, "stamp": stamp, "mutations": len(muts),
        "threat_triggers": threat, "idle_triggers": idle,
        "gaps": gaps, "install_lines": len(trace),
        "run_span_s": round(ts[-1] - ts[0], 1) if ts else None,
        "pcap": os.path.basename(pcap),
    }
    path = os.path.join(RESULTS, "summary_%s_%s.json" % (mode, stamp))
    with open(path, "w") as f:
        json.dump(summary, f, indent=2)
    print("  Saved: %s\n" % path)


# ----------------------------------------------------------------- helpers
def _read(path):
    try:
        with open(path) as f:
            return f.read()
    except Exception:
        return ""


def _tail(path, n):
    return "\n".join("     " + l for l in _read(path).splitlines()[-n:])


# ----------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description="One-shot experiment arm (Group 46)")
    ap.add_argument("--mode", required=True,
                    choices=["adaptive", "adaptive_floor", "baseline"])
    ap.add_argument("--duration", type=int, default=350)
    args = ap.parse_args()

    stamp = time.strftime("%Y%m%d_%H%M%S")
    print("\n" + "=" * 68)
    print("  MTD-SDN EXPERIMENT ARM  -  %s  (%ds)" % (args.mode.upper(), args.duration))
    print("=" * 68)

    try:
        s1_preflight(args.mode)
        s2_clean()
        ryu_log = s3_start_ryu(args.mode, stamp)
        pcap = s4_start_capture(args.mode, stamp)
        net, attacker, hosts = s5_topology()
        s6_warmup(net, ryu_log)
        s7_verify_mapping()
        s8_attack(attacker, args.duration)
        s9_teardown_and_save(args.mode, pcap)
        s10_summary(args.mode, stamp, pcap)
    except KeyboardInterrupt:
        print("\n\n  Interrupted - cleaning up.")
        teardown()
        sys.exit(130)
    except Exception as exc:
        import traceback
        print("FAIL")
        print("\n  UNEXPECTED ERROR: %s" % exc)
        traceback.print_exc()
        teardown()
        sys.exit(1)


if __name__ == "__main__":
    main()
