"""
Fingerprint-Resistant Mutation Module
======================================
When called by the MTD trigger, this module re-assigns virtual IP addresses
to hosts across the network using a STAGGERED installation strategy.

Instead of pushing all flow-rule changes simultaneously (which creates a
detectable spike that MTDSense can fingerprint), changes are spread across
a randomised time window with per-switch delays.

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

# ── Configuration ─────────────────────────────────────────────────────────────
MIN_STAGGER_DELAY = 0.5    # Minimum seconds between per-switch updates
MAX_STAGGER_DELAY = 3.0    # Maximum seconds between per-switch updates
IP_POOL_BASE      = "10.0.0."
IP_POOL_RANGE     = range(100, 200)   # Virtual IPs drawn from this pool
# ─────────────────────────────────────────────────────────────────────────────


class MutationModule:
    """
    Manages virtual IP reassignment with staggered, fingerprint-resistant
    installation across multiple switches.
    """

    def __init__(self, datapaths):
        """
        datapaths: dict { dpid: datapath } — all connected OVS switches.
        """
        self.datapaths      = datapaths
        self.ip_mapping     = {}   # { real_ip: virtual_ip }
        self.mutation_count = 0
        logger.info("MutationModule ready with %d datapath(s)", len(datapaths))

    # ── Public API ────────────────────────────────────────────────────────────

    def trigger_mutation(self, attacker_ip=None):
        """
        Entry point called by MTD trigger.
        Generates new IP mappings and installs them in a staggered fashion.
        """
        self.mutation_count += 1
        logger.info("=== Mutation #%d triggered (attacker=%s) ===",
                    self.mutation_count, attacker_ip or "unknown")

        new_mapping = self._generate_new_mapping()
        self._log_mutation(new_mapping, attacker_ip)
        self._staggered_install(new_mapping)
        self.ip_mapping = new_mapping

    # ── Mapping Generation ────────────────────────────────────────────────────

    def _generate_new_mapping(self):
        """
        Randomly assign new virtual IPs from the pool to all known real IPs.
        Ensures no two hosts get the same virtual IP.
        """
        available = random.sample(list(IP_POOL_RANGE), len(self.ip_mapping) + 10)
        new_mapping = {}
        idx = 0
        for real_ip in self.ip_mapping:
            new_virtual = IP_POOL_BASE + str(available[idx])
            new_mapping[real_ip] = new_virtual
            idx += 1
            logger.info("  Remapping %s → %s", real_ip, new_virtual)
        return new_mapping

    def add_host(self, real_ip):
        """Register a new host real IP into the mapping pool."""
        if real_ip not in self.ip_mapping:
            virtual = IP_POOL_BASE + str(random.choice(list(IP_POOL_RANGE)))
            self.ip_mapping[real_ip] = virtual
            logger.info("Host registered: %s → %s", real_ip, virtual)

    # ── Staggered Installation ────────────────────────────────────────────────

    def _staggered_install(self, new_mapping):
        """
        Push flow rule updates to each switch with a random delay between
        each one. This avoids the simultaneous-update spike that creates
        the timing fingerprint MTDSense detects.
        """
        switches = list(self.datapaths.values())
        random.shuffle(switches)   # Randomise order for additional unpredictability

        cumulative_delay = 0
        for datapath in switches:
            delay = random.uniform(MIN_STAGGER_DELAY, MAX_STAGGER_DELAY)
            cumulative_delay += delay
            Timer(cumulative_delay,
                  self._install_on_switch,
                  args=(datapath, new_mapping)).start()
            logger.debug("Switch %s scheduled at +%.2fs", datapath.id, cumulative_delay)

        logger.info("Staggered install across %d switches (total window: %.2fs)",
                    len(switches), cumulative_delay)

    def _install_on_switch(self, datapath, mapping):
        """
        Install updated flow rules for the new IP mapping on a single switch.
        Uses OpenFlow 1.3 flow_mod messages.
        """
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser

        for real_ip, virtual_ip in mapping.items():
            # Forward rule: translate virtual_ip → real_ip on ingress
            match_in = parser.OFPMatch(eth_type=0x0800, ipv4_dst=virtual_ip)
            actions_in = [
                parser.OFPActionSetField(ipv4_dst=real_ip),
                parser.OFPActionOutput(ofp.OFPP_NORMAL)
            ]
            self._add_flow(datapath, priority=100,
                           match=match_in, actions=actions_in)

            # Reverse rule: translate real_ip → virtual_ip on egress
            match_out = parser.OFPMatch(eth_type=0x0800, ipv4_src=real_ip)
            actions_out = [
                parser.OFPActionSetField(ipv4_src=virtual_ip),
                parser.OFPActionOutput(ofp.OFPP_NORMAL)
            ]
            self._add_flow(datapath, priority=100,
                           match=match_out, actions=actions_out)

        logger.info("Flow rules installed on switch %s", datapath.id)

    def _add_flow(self, datapath, priority, match, actions, hard_timeout=60):
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        mod    = parser.OFPFlowMod(
            datapath=datapath,
            priority=priority,
            match=match,
            instructions=inst,
            hard_timeout=hard_timeout,   # Rules expire automatically
            command=ofp.OFPFC_ADD
        )
        datapath.send_msg(mod)

    # ── Logging ───────────────────────────────────────────────────────────────

    def _log_mutation(self, new_mapping, attacker_ip):
        with open(MUTATION_LOG, 'a') as f:
            entry = {
                'timestamp':      time.strftime('%Y-%m-%d %H:%M:%S'),
                'mutation_count': self.mutation_count,
                'attacker_ip':    attacker_ip,
                'new_mapping':    new_mapping
            }
            f.write(json.dumps(entry) + '\n')

    def get_virtual_ip(self, real_ip):
        """Return the current virtual IP for a given real IP."""
        return self.ip_mapping.get(real_ip, real_ip)

    def get_real_ip(self, virtual_ip):
        """Reverse lookup: virtual IP → real IP."""
        for real, virtual in self.ip_mapping.items():
            if virtual == virtual_ip:
                return real
        return virtual_ip
