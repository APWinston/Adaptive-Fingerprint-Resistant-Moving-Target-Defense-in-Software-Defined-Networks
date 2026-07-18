"""
Parameterised MTD Evaluation Topology
=====================================
The fixed 5-host/2-switch topology in mtd_topo.py cannot answer a
scalability question, because scalability is about how the system behaves
as N changes. This module builds the same style of network for an
arbitrary host and switch count so N can be swept.

Layout (n_switches in a line, hosts round-robin across them):

    attacker ─┐
    h1 ───────┤
    h3 ───────┤── s1 ══ s2 ══ s3 ...
    h2 ─────────────────┤
    h4 ─────────────────┘

  - attacker is always on s1 (same position as the original topology)
  - host real IPs are 10.0.0.1 .. 10.0.0.N   (N <= 90)
  - attacker is 10.0.0.99
  - the mutation pool (10.0.0.100-199) is left clear

Real IPs stop at 90 deliberately: the mutation module draws virtual
addresses from 10.0.0.100-199, so a real IP in that range would collide
with the pool and be mistaken for a rewritten address by is_virtual_ip().

Used by evaluation/scalability_test.py. Can also be run standalone:

  sudo python3 topology/mtd_topo_scale.py --hosts 16 --switches 4

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import argparse
import time

MAX_REAL_HOSTS = 90          # 10.0.0.1 .. 10.0.0.90, below the mutation pool
ATTACKER_IP    = "10.0.0.99"


def build_scaled_net(n_hosts=4, n_switches=2, edge_bw=100, core_bw=1000,
                     edge_delay="2ms", core_delay="1ms",
                     controller_ip="127.0.0.1", controller_port=6633):
    """
    Build (but do not start) a scaled MTD topology.

    Returns (net, hosts, attacker, switches) so the caller can drive
    traffic programmatically rather than through the CLI.
    """
    if n_hosts > MAX_REAL_HOSTS:
        raise ValueError(
            f"n_hosts={n_hosts} exceeds {MAX_REAL_HOSTS}; real IPs would "
            f"collide with the mutation pool at 10.0.0.100-199"
        )
    if n_switches < 1:
        raise ValueError("n_switches must be >= 1")

    net = Mininet(controller=RemoteController, switch=OVSSwitch,
                  link=TCLink, autoSetMacs=True)

    net.addController('c0', controller=RemoteController,
                      ip=controller_ip, port=controller_port)

    # -- switches, linked in a line --------------------------------------
    switches = [net.addSwitch('s%d' % (i + 1), protocols='OpenFlow13')
                for i in range(n_switches)]
    for i in range(n_switches - 1):
        net.addLink(switches[i], switches[i + 1],
                    bw=core_bw, delay=core_delay)

    # -- attacker, always on s1 ------------------------------------------
    attacker = net.addHost('attacker', ip=ATTACKER_IP + '/24',
                           mac='00:00:00:00:00:99')
    net.addLink(attacker, switches[0], bw=edge_bw, delay=edge_delay)

    # -- protected hosts, round-robin across the switches ----------------
    hosts = []
    for i in range(n_hosts):
        h = net.addHost('h%d' % (i + 1), ip='10.0.0.%d/24' % (i + 1))
        net.addLink(h, switches[i % n_switches], bw=edge_bw, delay=edge_delay)
        hosts.append(h)

    return net, hosts, attacker, switches


def host_pairs(hosts, n_switches):
    """
    Pair hosts for concurrent iperf so that traffic crosses the switch
    fabric rather than hairpinning on one switch.

    Hosts are assigned round-robin, so host i sits on switch (i %
    n_switches). Pairing i with i + len/2 puts the two ends on different
    switches whenever len/2 is not a multiple of n_switches, which is the
    interesting case: it forces the core link to carry the load and lets
    the aggregate throughput actually saturate.
    """
    half = len(hosts) // 2
    return [(hosts[i], hosts[i + half]) for i in range(half)]


def main():
    ap = argparse.ArgumentParser(description="Scaled MTD topology (Group 46)")
    ap.add_argument("--hosts", type=int, default=4)
    ap.add_argument("--switches", type=int, default=2)
    ap.add_argument("--edge-bw", type=float, default=100)
    ap.add_argument("--core-bw", type=float, default=1000)
    args = ap.parse_args()

    setLogLevel('info')
    net, hosts, attacker, switches = build_scaled_net(
        n_hosts=args.hosts, n_switches=args.switches,
        edge_bw=args.edge_bw, core_bw=args.core_bw)

    info("*** Starting network (%d hosts, %d switches)\n"
         % (args.hosts, args.switches))
    net.start()
    time.sleep(2)
    info("*** Hosts: %s\n" % ", ".join("%s=%s" % (h.name, h.IP()) for h in hosts))
    info("*** Attacker: %s\n" % attacker.IP())
    CLI(net)
    net.stop()


if __name__ == '__main__':
    main()
