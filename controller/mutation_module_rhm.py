"""
RHM Mutation Module (Bidirectional Translation + Real-IP Shielding)
====================================================================
Replaces mutation_module.py for the RDR experiment. The original module
is left untouched so the existing results remain reproducible.

WHY THIS EXISTS
---------------
The original module translated the DESTINATION only:

    match ipv4_dst = <virtual>  ->  set ipv4_dst = <real>, output port

A probe sent to h1's virtual address therefore arrived at h1 with
dst = 10.0.0.1, and h1 replied from 10.0.0.1 - its REAL address. The
sender had addressed 10.0.0.147 and got an answer from 10.0.0.1, which
its stack discards as a source mismatch. ICMP echo replies were ignored
and TCP handshakes were reset. Virtual addresses were addressable but
unusable for anything stateful.

Consequently the only workable address was the real one, the attacker
scanned real addresses, mutation never touched the packets in flight, and
RDR measured ~0 - not because the defence failed, but because the
mutation was never in the attacker's path.

THE PIPELINE
------------
Three tables. Every rule is symmetric, so both directions of a flow are
rewritten and sockets match at both ends.

  TABLE 0 (source translation)
      ipv4_src = <real>     -> set ipv4_src = <virtual>, goto 1
      miss                  -> goto 1

  TABLE 1 (destination translation + shield)
      ipv4_dst = <virtual>  -> set ipv4_dst = <real>, goto 2   (prio 100)
      ipv4_dst = <real>     -> DROP                            (prio 90)
      miss                  -> goto 2

  TABLE 2 (L2 / microflow forwarding, unchanged behaviour)
      installed by the controller

Worked example, h1 (10.0.0.1 / v1) talking to h3 (10.0.0.3 / v3):

  h1 -> v3 :  t0 rewrites src to v1, t1 rewrites dst to 10.0.0.3
              h3 receives  src=v1  dst=10.0.0.3     (its own real address)
  h3 -> v1 :  t0 rewrites src to v3, t1 rewrites dst to 10.0.0.1
              h1 receives  src=v3  dst=10.0.0.1

Each end addresses the peer by virtual address and sees replies from that
same virtual address, so the connection completes. Each end still sees its
own real address as the destination, so the host stack accepts the packet.

EDGE-ONLY TRANSLATION (and why)
-------------------------------
A host's translation rules are installed ONLY on the switch that host is
attached to. An earlier version installed them on every switch and broke
every path longer than one hop.

The failure: h3 (on s2) pings the attacker (on s1). The request leaves
fine. The attacker replies to v3, and s1 - which also held h3's rules -
translated dst v3 -> 10.0.0.3 and forwarded the result to s2. s2 then saw
a REAL destination address arriving on a link and shielded it. Translate
at hop one, shield at hop two, drop. Only hosts sharing a switch with
their peer could talk.

With edge-only translation a real address is only ever produced by the
LAST switch on the path, inside its own table 1 -> table 2 handoff, and
never travels a link where another switch's shield could see it. Traffic
in flight always carries virtual addresses.

This requires knowing where each host lives, so register_host() takes the
dpid of the switch that first reported it. First report wins: a host's own
switch always raises packet_in before any switch the frame is flooded on
to, because the flood is what the controller does in response to that
first packet_in.

THE SHIELD IS NOT THE DEFENCE
-----------------------------
The prio-90 drop rule makes real addresses unreachable from the data
plane, so the virtual space is the only address space an attacker can
discover. That mirrors the OF-RHM deployment assumption, where real
addresses are never published and only virtual ones are resolvable.

It is deliberately present in BOTH the adaptive and the baseline arm. It
defines the environment, not the treatment. The treatment is the mutation
POLICY - threat-driven versus fixed-timer - and RDR compares the two arms
under an identical shield. A reviewer asking "isn't the shield doing the
work?" is answered by the baseline arm, which has the same shield and a
different RDR.

RULE LIFETIME
-------------
No hard_timeout. The original used hard_timeout=60 while adaptive
mutation intervals measured 30-59s, so translation rules could expire
before the next mutation replaced them and the network would silently
lose connectivity in the gap. Here stale rules are withdrawn explicitly
and nothing expires on its own.

Source rules need no withdrawal: their match (ipv4_src = real) is
unchanged by a mutation, so re-adding with the same match and priority
overwrites the action in place. Only destination rules, whose match is the
virtual address itself, must be deleted when that address moves.

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
MUTATION_LOG  = "logs/mutations.log"
INSTALL_TRACE = "logs/install_trace.log"
MAPPING_FILE  = "logs/current_mapping.json"

# -- Pipeline layout -----------------------------------------------------------
TABLE_SRC = 0
TABLE_DST = 1
TABLE_FWD = 2

PRIO_XLATE  = 100
PRIO_SHIELD = 90

# -- Configuration -------------------------------------------------------------
MIN_STAGGER_DELAY = 0.5
MAX_STAGGER_DELAY = 2.0
IP_POOL_BASE      = "10.0.0."
IP_POOL_RANGE     = range(100, 200)
ETH_IPV4          = 0x0800
# -----------------------------------------------------------------------------


def is_virtual_ip(ip):
    """True if the address comes from the mutation pool."""
    try:
        if not ip.startswith(IP_POOL_BASE):
            return False
        return int(ip.rsplit(".", 1)[1]) in IP_POOL_RANGE
    except (ValueError, IndexError):
        return False


class MutationModuleRHM:
    """
    stagger=True  -> staggered installation (adaptive)
    stagger=False -> simultaneous installation (baseline)
    """

    def __init__(self, datapaths, stagger=True):
        self.datapaths      = datapaths
        self.stagger        = stagger
        self.ip_mapping     = {}     # real -> virtual (current)
        self.host_dpid      = {}     # real -> dpid of the switch it hangs off
        self.prev_mapping   = {}
        self.mutation_count = 0
        self._trigger_ts    = 0.0
        self._detect_ts     = None
        self._shielded      = set()  # (dpid, real_ip) already shielded
        logger.info("MutationModuleRHM ready | mode=%s",
                    "STAGGERED" if stagger else "SIMULTANEOUS")

    # -- Host registration -----------------------------------------------------

    def register_host(self, real_ip, dpid=None):
        """
        Learn a host and make it reachable at its virtual address.

        dpid is the switch that reported it, and translation rules go on
        that switch ALONE - see the edge-only note in the module docstring.
        The shield goes on every switch, so a probe at a real address is
        dropped wherever it enters rather than being carried across the
        fabric first.

        The initial install matters. add_host() alone would assign a
        virtual address with no flow rules behind it while the shield
        makes the real address unreachable - the host would be cut off
        entirely until the first mutation happened to fire. Rules are
        therefore installed at registration, and mutations only remap
        them afterwards.

        Returns True if this was a newly registered host.
        """
        if is_virtual_ip(real_ip):
            return False
        if real_ip in self.ip_mapping:
            return False

        self.ip_mapping[real_ip] = self._fresh_virtual(exclude=set(self.ip_mapping.values()))
        if dpid is not None:
            self.host_dpid[real_ip] = dpid
        logger.info("Host registered: %s -> %s (edge switch s%s)",
                    real_ip, self.ip_mapping[real_ip], dpid)

        for dp in list(self.datapaths.values()):
            self._ensure_shield(dp, real_ip)
            if self._is_edge_for(dp.id, real_ip):
                self._install_host(dp, real_ip, self.ip_mapping[real_ip])
        self._export_mapping()
        return True

    def _is_edge_for(self, dpid, real_ip):
        """
        Is this switch the one that host hangs off?

        If the location was never learned we fall back to True - installing
        everywhere - so that a host whose dpid is unknown stays reachable
        rather than silently vanishing from the network.
        """
        known = self.host_dpid.get(real_ip)
        return True if known is None else known == dpid

    def install_all_on(self, datapath):
        """Program a switch that connected after hosts were already known."""
        for real_ip, virtual_ip in self.ip_mapping.items():
            self._ensure_shield(datapath, real_ip)
            if self._is_edge_for(datapath.id, real_ip):
                self._install_host(datapath, real_ip, virtual_ip)

    # -- Public API ------------------------------------------------------------

    def trigger_mutation(self, attacker_ip=None):
        self.mutation_count += 1
        self._trigger_ts = time.time()
        # Stamped by the threat engine at the moment of detection and
        # handed over by MTDTrigger. None in the baseline arm: a timer
        # tick responds to nothing, so it has no detection segment.
        self._detect_ts = getattr(self, "pending_detect_ts", None)
        logger.info("=== Mutation #%d triggered (attacker=%s) ===",
                    self.mutation_count, attacker_ip or "unknown")

        new_mapping = self._generate_new_mapping()
        if not new_mapping:
            logger.warning("Mutation #%d: no hosts registered, nothing to remap",
                           self.mutation_count)
            return

        self._log_mutation(new_mapping, attacker_ip)

        # prev_mapping must be set BEFORE the installs run: a staggered
        # install fires from timer threads later on, and each one needs to
        # know which virtual addresses to withdraw.
        self.prev_mapping = dict(self.ip_mapping)
        self.ip_mapping   = new_mapping
        self._export_mapping()

        if self.stagger:
            self._staggered_install(new_mapping)
        else:
            self._simultaneous_install(new_mapping)

    # -- Mapping generation ----------------------------------------------------

    def _fresh_virtual(self, exclude):
        pool = [IP_POOL_BASE + str(i) for i in IP_POOL_RANGE]
        available = [ip for ip in pool if ip not in exclude]
        return random.choice(available)

    def _generate_new_mapping(self):
        """
        Draw a fresh virtual address for every host.

        random.sample over the pool guarantees the new addresses are
        distinct from each other. They are also drawn away from the
        outgoing mapping, so that every host genuinely moves - a host that
        happened to redraw its own current address would be a mutation
        that did not mutate, and the attacker's stale knowledge of it
        would still be valid.
        """
        hosts = list(self.ip_mapping.keys())
        if not hosts:
            return {}
        current = set(self.ip_mapping.values())
        pool = [IP_POOL_BASE + str(i) for i in IP_POOL_RANGE if
                (IP_POOL_BASE + str(i)) not in current]
        if len(pool) < len(hosts):
            # pool exhausted; fall back to allowing reuse of old addresses
            pool = [IP_POOL_BASE + str(i) for i in IP_POOL_RANGE]
        chosen = random.sample(pool, len(hosts))
        new_mapping = {}
        for real_ip, virtual_ip in zip(hosts, chosen):
            new_mapping[real_ip] = virtual_ip
            logger.info("  Remapping %s -> %s", real_ip, virtual_ip)
        return new_mapping

    # -- Installation strategies -----------------------------------------------

    def _staggered_install(self, new_mapping):
        switches = list(self.datapaths.values())
        random.shuffle(switches)
        cumulative = 0.0
        for dp in switches:
            cumulative += random.uniform(MIN_STAGGER_DELAY, MAX_STAGGER_DELAY)
            Timer(cumulative, self._install_on_switch,
                  args=(dp, new_mapping, cumulative)).start()
        logger.info("Staggered install across %d switches (window %.2fs)",
                    len(switches), cumulative)

    def _simultaneous_install(self, new_mapping):
        for dp in list(self.datapaths.values()):
            self._install_on_switch(dp, new_mapping, 0.0)
        logger.info("Simultaneous install across %d switches (window 0.00s)",
                    len(self.datapaths))

    def _install_on_switch(self, datapath, mapping, scheduled_delay):
        """Apply one mutation's rules to a single switch."""
        try:
            # Only the hosts that live on THIS switch. A switch holding
            # rules for a remote host is what broke every multi-hop path.
            local = [r for r in mapping if self._is_edge_for(datapath.id, r)]

            for real_ip in local:
                old_virtual = self.prev_mapping.get(real_ip)
                if old_virtual and old_virtual != mapping[real_ip]:
                    self._del_dst(datapath, old_virtual)

            for real_ip in local:
                self._install_host(datapath, real_ip, mapping[real_ip])

            self._log_install(datapath.id, scheduled_delay)
            logger.info("Rules installed on switch %s (%d local hosts)",
                        datapath.id, len(local))
        except Exception as exc:
            # A timer thread that raises would die silently and this switch
            # would keep the old mapping forever, which looks like a
            # mutation that half-happened.
            logger.exception("Install failed on switch %s: %s", datapath.id, exc)

    def _install_host(self, datapath, real_ip, virtual_ip):
        """Both directions for one host on one switch."""
        self._add_dst(datapath, virtual_ip, real_ip)
        self._add_src(datapath, real_ip, virtual_ip)

    # -- Rule primitives -------------------------------------------------------

    def _add_src(self, datapath, real_ip, virtual_ip):
        """TABLE 0:  ipv4_src=real -> set ipv4_src=virtual, goto TABLE 1."""
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_IPV4, ipv4_src=real_ip)
        inst = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionSetField(ipv4_src=virtual_ip)]),
            parser.OFPInstructionGotoTable(TABLE_DST),
        ]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=TABLE_SRC, priority=PRIO_XLATE,
            command=ofp.OFPFC_ADD, match=match, instructions=inst))

    def _add_dst(self, datapath, virtual_ip, real_ip):
        """TABLE 1:  ipv4_dst=virtual -> set ipv4_dst=real, goto TABLE 2."""
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_IPV4, ipv4_dst=virtual_ip)
        inst = [
            parser.OFPInstructionActions(
                ofp.OFPIT_APPLY_ACTIONS,
                [parser.OFPActionSetField(ipv4_dst=real_ip)]),
            parser.OFPInstructionGotoTable(TABLE_FWD),
        ]
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=TABLE_DST, priority=PRIO_XLATE,
            command=ofp.OFPFC_ADD, match=match, instructions=inst))

    def _del_dst(self, datapath, virtual_ip):
        """
        Withdraw a retired virtual address.

        DELETE_STRICT, not DELETE: a non-strict delete matches any flow
        whose match is covered by the supplied one, which risks taking the
        shield rules with it. Strict deletion removes exactly the entry
        with this match and priority.
        """
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_IPV4, ipv4_dst=virtual_ip)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=TABLE_DST, priority=PRIO_XLATE,
            command=ofp.OFPFC_DELETE_STRICT, match=match,
            out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY))

    def _ensure_shield(self, datapath, real_ip):
        """
        TABLE 1:  ipv4_dst=real -> drop.

        Installed once per (switch, host) and never mutated - real
        addresses do not move. Kept out of the install trace on purpose:
        the trace measures mutation cost, and a shield is not part of a
        mutation.

        An empty instruction list is a drop in OpenFlow 1.3.
        """
        key = (datapath.id, real_ip)
        if key in self._shielded:
            return
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        match = parser.OFPMatch(eth_type=ETH_IPV4, ipv4_dst=real_ip)
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=TABLE_DST, priority=PRIO_SHIELD,
            command=ofp.OFPFC_ADD, match=match, instructions=[]))
        self._shielded.add(key)
        logger.info("Shield installed on s%s for %s", datapath.id, real_ip)

    # -- Logging ---------------------------------------------------------------

    def _export_mapping(self):
        """
        Publish the live real -> virtual mapping to disk.

        With the shield in place a real address is unreachable, so any test
        that wants to send traffic to a host has to know its CURRENT
        virtual address. mutations.log is not usable for this: it only
        records mutations, so before the first one fires it says nothing at
        all, and after one fires the reader has to guess whether the last
        line is still current. This file is rewritten on every registration
        and every mutation and always describes now.

        Written whole each time rather than appended: a stale half-file is
        worse than no file, because a test would silently send to an
        address that has already moved and record the loss as a throughput
        result.
        """
        try:
            with open(MAPPING_FILE, 'w') as f:
                json.dump({
                    'updated':        round(time.time(), 4),
                    'mutation_count': self.mutation_count,
                    'mapping':        self.ip_mapping,
                }, f, indent=2)
        except IOError as exc:
            logger.warning("Could not export mapping: %s", exc)

    def _log_mutation(self, new_mapping, attacker_ip):
        with open(MUTATION_LOG, 'a') as f:
            f.write(json.dumps({
                'timestamp':      time.strftime('%Y-%m-%d %H:%M:%S'),
                'wall_ts':        round(self._trigger_ts, 4),
                'mutation_count': self.mutation_count,
                'attacker_ip':    attacker_ip,
                'mode':           'staggered' if self.stagger else 'simultaneous',
                'new_mapping':    new_mapping,
            }) + '\n')

    def _log_install(self, switch_id, scheduled_delay):
        """Same schema as the original module, so existing evaluation reads it."""
        install_ts = time.time()
        with open(INSTALL_TRACE, 'a') as f:
            entry = {
                'mutation_id':   self.mutation_count,
                'switch':        switch_id,
                'mode':          'staggered' if self.stagger else 'simultaneous',
                'trigger_ts':    round(self._trigger_ts, 4),
                'install_ts':    round(install_ts, 4),
                'install_delay': round(install_ts - self._trigger_ts, 4),
                'scheduled':     round(scheduled_delay, 4),
            }
            # Only written when detection actually happened. compute_kpis
            # reports the detection segments as N/A when the key is absent,
            # rather than falling back to trigger_ts and reporting a zero
            # that was never measured.
            if self._detect_ts is not None:
                entry['detect_ts']         = round(self._detect_ts, 4)
                entry['detect_to_trigger'] = round(self._trigger_ts - self._detect_ts, 4)
                entry['detect_to_install'] = round(install_ts - self._detect_ts, 4)
            f.write(json.dumps(entry) + '\n')

    # -- Lookups ---------------------------------------------------------------

    def get_virtual_ip(self, real_ip):
        return self.ip_mapping.get(real_ip, real_ip)

    def get_real_ip(self, virtual_ip):
        for real, virtual in self.ip_mapping.items():
            if virtual == virtual_ip:
                return real
        return virtual_ip
