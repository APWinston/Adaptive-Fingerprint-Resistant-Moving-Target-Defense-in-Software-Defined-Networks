"""
MTD Evaluation Topology
========================
Creates a Mininet network with:
  - 1 attacker host  (h_attacker)
  - 4 legitimate hosts (h1 - h4)
  - 2 Open vSwitch switches (s1, s2)
  - Remote Ryu controller

Layout:
  h_attacker ─┐
  h1 ─────────┤
  h2 ─────────┤── s1 ── s2 ──┬── h3
              │               └── h4
  (attacker connected to s1 for realistic scenario)

Run with:
  sudo python topology/mtd_topo.py
  sudo python topology/mtd_topo.py --mode baseline

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

from mininet.net import Mininet
from mininet.node import RemoteController, OVSSwitch
from mininet.cli import CLI
from mininet.log import setLogLevel, info
from mininet.link import TCLink
import argparse
import time


def build_topology(mode='adaptive'):
    """Build and start the MTD evaluation network."""

    setLogLevel('info')
    info("*** Building MTD topology (mode: %s)\n" % mode)

    net = Mininet(
        controller=RemoteController,
        switch=OVSSwitch,
        link=TCLink,
        autoSetMacs=True
    )

    # ── Controller ────────────────────────────────────────────────────────────
    info("*** Adding remote Ryu controller\n")
    c0 = net.addController(
        'c0',
        controller=RemoteController,
        ip='127.0.0.1',
        port=6633
    )

    # ── Switches ──────────────────────────────────────────────────────────────
    info("*** Adding switches\n")
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    s2 = net.addSwitch('s2', protocols='OpenFlow13')

    # ── Hosts ─────────────────────────────────────────────────────────────────
    info("*** Adding hosts\n")
    h_attacker = net.addHost('attacker', ip='10.0.0.99/24', mac='00:00:00:00:00:99')
    h1 = net.addHost('h1', ip='10.0.0.1/24', mac='00:00:00:00:00:01')
    h2 = net.addHost('h2', ip='10.0.0.2/24', mac='00:00:00:00:00:02')
    h3 = net.addHost('h3', ip='10.0.0.3/24', mac='00:00:00:00:00:03')
    h4 = net.addHost('h4', ip='10.0.0.4/24', mac='00:00:00:00:00:04')

    # ── Links ─────────────────────────────────────────────────────────────────
    info("*** Adding links\n")
    # Hosts to s1
    net.addLink(h_attacker, s1, bw=100, delay='2ms')
    net.addLink(h1, s1, bw=100, delay='2ms')
    net.addLink(h2, s1, bw=100, delay='2ms')

    # Hosts to s2
    net.addLink(h3, s2, bw=100, delay='2ms')
    net.addLink(h4, s2, bw=100, delay='2ms')

    # Switch interconnect
    net.addLink(s1, s2, bw=1000, delay='1ms')

    # ── Start Network ─────────────────────────────────────────────────────────
    info("*** Starting network\n")
    net.start()

    # Wait for controller connection
    time.sleep(2)
    info("*** Network ready\n")
    info("*** Hosts: attacker=%s, h1=%s, h2=%s, h3=%s, h4=%s\n" %
         (h_attacker.IP(), h1.IP(), h2.IP(), h3.IP(), h4.IP()))

    # ── Run CLI ───────────────────────────────────────────────────────────────
    info("*** Running CLI (type 'help' for commands, 'exit' to quit)\n")
    info("*** Tip: run 'attacker ping h1' to test, then run attack script\n")
    CLI(net)

    # ── Cleanup ───────────────────────────────────────────────────────────────
    info("*** Stopping network\n")
    net.stop()


def simple_topology():
    """Minimal 2-host topology for quick testing."""
    setLogLevel('info')
    net = Mininet(controller=RemoteController, switch=OVSSwitch, autoSetMacs=True)
    c0 = net.addController('c0', ip='127.0.0.1', port=6633)
    s1 = net.addSwitch('s1', protocols='OpenFlow13')
    h1 = net.addHost('h1', ip='10.0.0.1/24')
    h2 = net.addHost('h2', ip='10.0.0.2/24')
    net.addLink(h1, s1)
    net.addLink(h2, s1)
    net.start()
    CLI(net)
    net.stop()


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='MTD SDN Topology')
    parser.add_argument('--mode', choices=['adaptive', 'baseline', 'simple'],
                        default='adaptive', help='Topology/run mode')
    args = parser.parse_args()

    if args.mode == 'simple':
        simple_topology()
    else:
        build_topology(mode=args.mode)
