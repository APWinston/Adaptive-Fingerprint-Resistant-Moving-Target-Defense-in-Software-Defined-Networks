"""
Reconnaissance Disruption Rate (RDR) Experiment
===============================================
Measures the KPI as specified:

    RDR = 1 - (Successful Reconnaissance / Total Reconnaissance Attempts)

WHY THE OLD NUMBER WAS ZERO
---------------------------
RDR was never actually measured. compute_kpis.py reported
mutations / threat_events, which is a cooldown pass rate, not a
disruption rate. The true value under the old architecture was ~0,
because the attacker scanned REAL addresses while mutation only rewrote
traffic aimed at VIRTUAL ones. The mutation was never in the attacker's
packet path, so no parameter could change the result - which is exactly
why RDR did not respond to tuning.

Requires controller/mtd_controller_rhm.py, whose pipeline makes virtual
addresses the only usable address space.

THE ATTACK MODEL
----------------
Reconnaissance then exploitation, which is how MTD is supposed to be
defeated and how OF-RHM evaluates it:

  Phase 1 - DISCOVERY. The attacker sweeps the virtual address space once
      and records every address that answers. This is its intelligence.

  Phase 2 - EXPLOITATION. For a fixed window it repeatedly probes the
      addresses it discovered. Every probe is one reconnaissance attempt.
      A probe that gets a reply is a success; one that does not is an
      attempt the defence disrupted.

The attacker does NOT rescan during phase 2. That is the whole point: an
attacker who re-runs discovery before every packet is not being disrupted,
it is just paying for a scan each time, and RDR would read 0 by
construction. Real reconnaissance is expensive and gets reused, and MTD
attacks the shelf life of that reused knowledge.

WHY THIS IS NOT MEASURING THE SHIELD
------------------------------------
The shield (real addresses unreachable) is present in BOTH arms, and the
attacker never probes real addresses here - only the virtual ones it
legitimately discovered and which legitimately answered. Every failure
counted is an address that WORKED at discovery and stopped working
because it moved. Run both arms and compare: the shield is identical, so
any difference in RDR comes from the mutation policy alone.

USAGE
-----
Start the controller first, in another terminal:

    ryu-manager controller/mtd_controller_rhm.py                  # adaptive
    MTD_MODE=baseline ryu-manager controller/mtd_controller_rhm.py

Then:

    sudo python3 evaluation/rdr_test.py --label adaptive --window 180
    sudo python3 evaluation/rdr_test.py --label baseline --window 180

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import argparse
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from mininet.log import setLogLevel, info
from topology.mtd_topo import build_topology  # noqa: F401  (kept for reference)
from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.link import TCLink

RESULTS_DIR   = "results"
POOL_SWEEP    = "10.0.0.100-199"
ATTACKER_IP   = "10.0.0.99"


# ---------------------------------------------------------------- topology
def build_net():
    """Same 5-host / 2-switch topology as mtd_topo.py, built without the CLI."""
    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)
    net.addController('c0', controller=RemoteController,
                      ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    attacker = net.addHost('attacker', ip=ATTACKER_IP + '/24',
                           mac='00:00:00:00:00:99')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    for h in (attacker, h1, h2):
        net.addLink(h, s1, bw=100, delay='2ms')
    for h in (h3, h4):
        net.addLink(h, s2, bw=100, delay='2ms')
    net.addLink(s1, s2, bw=1000, delay='1ms')
    return net, attacker, [h1, h2, h3, h4]


# ---------------------------------------------------------------- attacker
def discover(attacker):
    """
    Phase 1: sweep the virtual pool and record what answers.

    -sn is a host-discovery sweep with no port scan. -n skips DNS. On a
    local segment nmap resolves these by ARP, which the controller's proxy
    answers for live virtual addresses only, so what comes back is exactly
    the current mapping.
    """
    out = attacker.cmd('nmap -sn -n --host-timeout 3s %s' % POOL_SWEEP)
    found = re.findall(r'Nmap scan report for (10\.0\.0\.\d+)', out)
    return sorted(set(found))


def probe(attacker, vip):
    """
    One reconnaissance attempt against one previously discovered address.

    A single ICMP echo with a 1s deadline. The ARP cache is deliberately
    NOT flushed between probes: a real attacker reuses what it learned,
    and flushing would silently re-resolve the address and hide the very
    disruption being measured.
    """
    out = attacker.cmd('ping -c 1 -W 1 -n %s' % vip)
    return ' 0% packet loss' in out or '1 received' in out


# ---------------------------------------------------------------- experiment
def run(label, window, probe_interval, warmup):
    setLogLevel('info')
    os.makedirs(RESULTS_DIR, exist_ok=True)

    net, attacker, hosts = build_net()
    net.start()
    time.sleep(3)

    # The controller only learns a host once it has seen traffic from it,
    # and only shields/translates once it has learned it. Without this the
    # virtual space is empty and discovery returns nothing.
    info("*** Warm-up: registering hosts with the controller\n")
    net.pingAll(timeout='1')
    time.sleep(warmup)

    info("*** Phase 1: discovery sweep of %s\n" % POOL_SWEEP)
    discovered = discover(attacker)
    info("*** Discovered %d virtual addresses: %s\n"
         % (len(discovered), ", ".join(discovered)))

    if not discovered:
        info("*** ABORT: nothing discovered. Is mtd_controller_rhm.py running,\n")
        info("***        and did the warm-up pingAll succeed?\n")
        net.stop()
        return None

    info("*** Phase 2: exploiting discovered addresses for %ds\n" % window)
    t0 = time.time()
    attempts = 0
    successes = 0
    timeline = []
    first_failure = None

    while time.time() - t0 < window:
        for vip in discovered:
            ok = probe(attacker, vip)
            attempts += 1
            if ok:
                successes += 1
            elif first_failure is None:
                first_failure = round(time.time() - t0, 2)
            timeline.append({
                't': round(time.time() - t0, 2),
                'vip': vip,
                'ok': ok,
            })
        time.sleep(probe_interval)

    net.stop()

    rdr = round(1.0 - (successes / attempts), 4) if attempts else None
    result = {
        'label':            label,
        'discovered':       discovered,
        'attempts':         attempts,
        'successes':        successes,
        'failures':         attempts - successes,
        'rdr':              rdr,
        'window_s':         window,
        'probe_interval_s': probe_interval,
        'first_failure_s':  first_failure,
        'timeline':         timeline,
    }

    stamp = time.strftime("%Y%m%d_%H%M%S")
    path = os.path.join(RESULTS_DIR, "rdr_%s_%s.json" % (label, stamp))
    with open(path, 'w') as f:
        json.dump(result, f, indent=2)

    line = "=" * 64
    print("\n" + line)
    print("  RDR RESULT  -  %s" % label)
    print(line)
    print("  Addresses discovered      : %d" % len(discovered))
    print("  Reconnaissance attempts   : %d" % attempts)
    print("  Successful reconnaissance : %d" % successes)
    print("  Disrupted                 : %d" % (attempts - successes))
    print("  RDR = 1 - %d/%d           = %s" % (successes, attempts, rdr))
    if first_failure is not None:
        print("  Attacker knowledge went stale after %.2fs" % first_failure)
    else:
        print("  Attacker knowledge never went stale in this window.")
    print(line)
    print("  Saved: %s" % path)
    print("\n  Compare against the other arm. Both run the same shield, so a")
    print("  difference in RDR is a difference in mutation policy, not in")
    print("  reachability.")
    return result


def main():
    ap = argparse.ArgumentParser(description="RDR experiment (Group 46)")
    ap.add_argument("--label", default="adaptive",
                    help="tag for the output file; use the controller mode")
    ap.add_argument("--window", type=int, default=180,
                    help="phase 2 duration in seconds (keep equal across arms)")
    ap.add_argument("--probe-interval", type=float, default=2.0,
                    help="seconds between probe rounds")
    ap.add_argument("--warmup", type=int, default=5,
                    help="seconds to settle after registration before discovery")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("This must run as root (Mininet). Try: sudo python3 %s" % sys.argv[0])
        sys.exit(1)

    run(args.label, args.window, args.probe_interval, args.warmup)


if __name__ == '__main__':
    main()
