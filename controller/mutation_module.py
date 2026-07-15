"""
Fingerprint-Resistant Mutation Module
======================================
When called by the MTD trigger, this module re-assigns virtual IP addresses
to hosts across the network.

Two installation strategies are supported so the two systems can be
compared fairly:

  STAGGERED (adaptive, default)
      Each switch is programmed after its own independent random delay
      (MIN_STAGGER_DELAY..MAX_STAGGER_DELAY), in randomised order. No
      synchronised burst is ever emitted, so a fingerprinting attacker
      such as MTDSense has no spike to lock onto.

  SIMULTANEOUS (baseline)
      All switches are programmed at the same instant, reproducing the
      behaviour of conventional fixed-interval MTD. This produces the
      sharp, detectable burst that fingerprinting tools rely on.

Select with:  MutationModule(datapaths, stagger=False)   -> simultaneous

The module also writes a high-resolution INSTALL TRACE
(logs/install_trace.log): one entry per switch recording the exact moment
its flow rules were installed. That trace is the raw evidence used to
compute Fingerprint Resistance (ARI), Response Time, and to label windows
for the real classifier.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

import random
import time
import logging
import json
import os
from threading import Timer

logger = logging.getLogger(__name__)
os.makedirs("logs", exist_ok=True)
MUTATION_LOG = "logs/mutations.log"
INSTALL_TRACE = "logs/install_trace.log"

# -- Configuration -------------------------------------------------------------
MIN_STAGGER_DELAY = 0.5    # Minimum seconds between per-switch updates
MAX_STAGGER_DELAY = 2.0    # Maximum seconds between per-switch updates
IP_POOL_BASE      = "10.0.0."
IP_POOL_RANGE     = range(100, 200)   # Virtual IPs drawn from this pool
# -----------------------------------------------------------------------------


def is_virtual_ip(ip):
    """
    True if the address comes from the mutation pool.

    Guards against a subtle self-poisoning bug: after a mutation the
    defence rewrites source addresses, so rewritten packets can reach the
    controller and be mistaken for newly discovered hosts. Registering a
    virtual address as a host would make the mapping grow with phantom
    entries and mutate its own pool.
    """
    try:
        if not ip.startswith(IP_POOL_BASE):
            return False
        last = int(ip.rsplit(".", 1)[1])
        return last in IP_POOL_RANGE
    except (ValueError, IndexError):
        return False


class MutationModule:
    """
    Manages virtual IP reassignment.

    stagger=True  -> fingerprint-resistant staggered installation (adaptive)
    stagger=False -> simultaneous installation (conventional baseline)
    """

    def __init__(self, datapaths, stagger=True, port_resolver=None):
        """
        port_resolver(dpid, real_ip) -> switch port, or None if unknown.
        Supplied by the controller, which learns MAC/port bindings. Used so a
        translated packet can be sent straight out of the correct port rather
        than relying on OFPP_NORMAL, whose behaviour varies by switch setup.
        """
        self.datapaths      = datapaths
        self.stagger        = stagger
        self.port_resolver  = port_resolver
        self.ip_mapping     = {}
        self.prev_mapping   = {}
        self.mutation_count = 0
        self._trigger_ts    = 0.0
        logger.info("MutationModule ready with %d datapath(s) | mode=%s",
                    len(datapaths), "STAGGERED" if stagger else "SIMULTANEOUS")

    # -- Public API ------------------------------------------------------------

    def trigger_mutation(self, attacker_ip=None):
        self.mutation_count += 1
        self._trigger_ts = time.time()
        logger.info("=== Mutation #%d triggered (attacker=%s) ===",
                    self.mutation_count, attacker_ip or "unknown")

        new_mapping = self._generate_new_mapping()
        self._log_mutation(new_mapping, attacker_ip)

        if self.stagger:
            self._staggered_install(new_mapping)
        else:
            self._simultaneous_install(new_mapping)

        self.prev_mapping = dict(self.ip_mapping)
        self.ip_mapping   = new_mapping

    # -- Mapping generation ----------------------------------------------------

    def _generate_new_mapping(self):
        available = random.sample(list(IP_POOL_RANGE), len(self.ip_mapping) + 10)
        new_mapping = {}
        idx = 0
        for real_ip in self.ip_mapping:
            new_mapping[real_ip] = IP_POOL_BASE + str(available[idx])
            idx += 1
            logger.info("  Remapping %s -> %s", real_ip, new_mapping[real_ip])
        return new_mapping

    def add_host(self, real_ip):
        if is_virtual_ip(real_ip):
            return                       # never register a rewritten address
        if real_ip not in self.ip_mapping:
            virtual = IP_POOL_BASE + str(random.choice(list(IP_POOL_RANGE)))
            self.ip_mapping[real_ip] = virtual
            logger.info("Host registered: %s -> %s", real_ip, virtual)

    # -- Installation strategies -----------------------------------------------

    def _staggered_install(self, new_mapping):
        """Adaptive: randomised order, independent random delay per switch."""
        switches = list(self.datapaths.values())
        random.shuffle(switches)

        cumulative_delay = 0
        for datapath in switches:
            delay = random.uniform(MIN_STAGGER_DELAY, MAX_STAGGER_DELAY)
            cumulative_delay += delay
            Timer(cumulative_delay,
                  self._install_on_switch,
                  args=(datapath, new_mapping, cumulative_delay)).start()
            logger.debug("Switch %s scheduled at +%.2fs", datapath.id, cumulative_delay)

        logger.info("Staggered install across %d switches (window: %.2fs)",
                    len(switches), cumulative_delay)

    def _simultaneous_install(self, new_mapping):
        """Baseline: every switch programmed at once -> detectable burst."""
        switches = list(self.datapaths.values())
        for datapath in switches:
            self._install_on_switch(datapath, new_mapping, 0.0)
        logger.info("Simultaneous install across %d switches (window: 0.00s)",
                    len(switches))

    # -- Rule installation -----------------------------------------------------

    def _install_on_switch(self, datapath, mapping, scheduled_delay):
        """
        Install the mutation rules on one switch.

        DESTINATION-ONLY TRANSLATION
        ----------------------------
        Only traffic addressed to a virtual IP is rewritten:

            match ipv4_dst = <virtual>   ->   set ipv4_dst = <real>, forward

        An earlier design also rewrote ipv4_src on every packet leaving a
        host. That rule matched ALL of the host's traffic, including normal
        host-to-host flows, rewriting their source to an address no peer
        could resolve - which silently broke every flow in the network.
        Translating the destination only leaves legitimate real-IP traffic
        completely untouched, while anything using a virtual address is
        transparently delivered to the real host.

        Stale rules from the previous mapping are withdrawn first, so an
        address the attacker learned before the mutation stops working
        immediately rather than lingering until its timeout.
        """
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser

        # 1. withdraw the previous mapping's rules
        for _, old_virtual in self.prev_mapping.items():
            if old_virtual in mapping.values():
                continue                      # still in use, leave it
            self._del_flow(datapath, parser.OFPMatch(eth_type=0x0800,
                                                     ipv4_dst=old_virtual))

        # 2. install the new mapping
        for real_ip, virtual_ip in mapping.items():
            out_port = None
            if self.port_resolver:
                out_port = self.port_resolver(datapath.id, real_ip)
            if out_port is None:
                out_port = ofp.OFPP_FLOOD     # port not learned yet on this switch

            match = parser.OFPMatch(eth_type=0x0800, ipv4_dst=virtual_ip)
            actions = [
                parser.OFPActionSetField(ipv4_dst=real_ip),
                parser.OFPActionOutput(out_port)
            ]
            self._add_flow(datapath, 100, match, actions)

        self._log_install(datapath.id, scheduled_delay)
        logger.info("Flow rules installed on switch %s (%d mappings)",
                    datapath.id, len(mapping))

    def _del_flow(self, datapath, match):
        """Withdraw a mutation rule (also emits a FLOW_MOD)."""
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        mod = parser.OFPFlowMod(
            datapath=datapath, command=ofp.OFPFC_DELETE,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
            priority=100, match=match)
        datapath.send_msg(mod)

    def _add_flow(self, datapath, priority, match, actions, hard_timeout=60):
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod    = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match,
            instructions=inst, hard_timeout=hard_timeout, command=ofp.OFPFC_ADD)
        datapath.send_msg(mod)

    # -- Logging ---------------------------------------------------------------

    def _log_mutation(self, new_mapping, attacker_ip):
        with open(MUTATION_LOG, 'a') as f:
            f.write(json.dumps({
                'timestamp':      time.strftime('%Y-%m-%d %H:%M:%S'),
                'mutation_count': self.mutation_count,
                'attacker_ip':    attacker_ip,
                'mode':           'staggered' if self.stagger else 'simultaneous',
                'new_mapping':    new_mapping
            }) + '\n')

    def _log_install(self, switch_id, scheduled_delay):
        install_ts = time.time()
        with open(INSTALL_TRACE, 'a') as f:
            f.write(json.dumps({
                'mutation_id':   self.mutation_count,
                'switch':        switch_id,
                'mode':          'staggered' if self.stagger else 'simultaneous',
                'trigger_ts':    round(self._trigger_ts, 4),
                'install_ts':    round(install_ts, 4),
                'install_delay': round(install_ts - self._trigger_ts, 4),
                'scheduled':     round(scheduled_delay, 4)
            }) + '\n')

    def get_virtual_ip(self, real_ip):
        return self.ip_mapping.get(real_ip, real_ip)

    def get_real_ip(self, virtual_ip):
        for real, virtual in self.ip_mapping.items():
            if virtual == virtual_ip:
                return real
        return virtual_ip
