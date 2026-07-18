"""
Threat Scoring Engine
=====================
Monitors OpenFlow PacketIn events and assigns a threat score to each
source IP based on reconnaissance behaviour. When a score exceeds
THREAT_THRESHOLD it signals the MTD trigger to fire a mutation.

SCORING DESIGN
--------------
The engine must fire on reconnaissance but stay silent during normal
traffic. Two signals are used:

  Port sweeping   - each newly probed destination port scores +5.
                    An Nmap sweep touches hundreds of ports and trips the
                    threshold almost immediately.

  ARP sweeping    - normal hosts ARP for their few peers, so the first
                    ARP_FREE_TARGETS distinct targets are free. Only a host
                    ARPing for MORE targets than that (address sweeping)
                    starts scoring. This prevents ordinary traffic such as
                    a Mininet 'pingall' from being mistaken for an attack.

Virtual addresses from the mutation pool are never scored: they are the
defence's own rewritten addresses, not real sources.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, set_ev_cls
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp
import time
import logging
import json
import os

# -- Configuration -------------------------------------------------------------
THREAT_THRESHOLD   = 10     # Score at which a mutation fires (~2 new ports)
SCAN_WEIGHT        = 5      # Points per newly probed destination port
ARP_FREE_TARGETS   = 4      # Distinct ARP targets allowed before scoring
ARP_TARGET_WEIGHT  = 2      # Points per distinct ARP target beyond the free ones
HIGH_RATE_WEIGHT   = 15     # Points when packet rate exceeds RATE_LIMIT
RATE_LIMIT         = 50     # Packets/sec threshold for the rate penalty
DECAY_INTERVAL     = 10     # Seconds of quiet before decay starts
DECAY_AMOUNT       = 5      # Points removed per decay cycle
VIRTUAL_PREFIX     = "10.0.0."
VIRTUAL_LOW        = 100    # Mutation pool lower bound
VIRTUAL_HIGH       = 199    # Mutation pool upper bound
LOG_FILE           = "logs/threat_scores.log"
# -----------------------------------------------------------------------------

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ThreatEngine] %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)
os.makedirs("logs", exist_ok=True)


def is_virtual_ip(ip):
    """True if the address belongs to the mutation pool (a rewritten address)."""
    try:
        if not ip.startswith(VIRTUAL_PREFIX):
            return False
        last = int(ip.rsplit(".", 1)[1])
        return VIRTUAL_LOW <= last <= VIRTUAL_HIGH
    except (ValueError, IndexError):
        return False


class ThreatScoringEngine(app_manager.RyuApp):
    """Passive traffic monitor building per-IP threat scores."""

    def __init__(self, *args, **kwargs):
        super(ThreatScoringEngine, self).__init__(*args, **kwargs)
        self.threat_scores = {}
        self.mutation_callback = None
        logger.info("Threat Scoring Engine initialised. Threshold=%d "
                    "(port +%d, ARP +%d after %d free targets)",
                    THREAT_THRESHOLD, SCAN_WEIGHT, ARP_TARGET_WEIGHT, ARP_FREE_TARGETS)

    # -- Event handler ---------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt = packet.Packet(ev.msg.data)
        if pkt.get_protocol(ethernet.ethernet) is None:
            return

        ip_layer  = pkt.get_protocol(ipv4.ipv4)
        arp_layer = pkt.get_protocol(arp.arp)

        if ip_layer:
            self._process_ip(pkt, ip_layer)
        elif arp_layer:
            self._process_arp(arp_layer)

    # -- Processing ------------------------------------------------------------

    def _process_ip(self, pkt, ip_layer):
        src = ip_layer.src
        if is_virtual_ip(src):
            return                      # our own rewritten address, not a source
        self._ensure_entry(src)

        tcp_layer = pkt.get_protocol(tcp.tcp)
        udp_layer = pkt.get_protocol(udp.udp)

        if tcp_layer:
            self._add_port(src, tcp_layer.dst_port)
        elif udp_layer:
            self._add_port(src, udp_layer.dst_port)

        self._check_rate(src)
        self._maybe_decay(src)
        self._check_threshold(src)

    def _process_arp(self, arp_layer):
        src = arp_layer.src_ip
        if is_virtual_ip(src):
            return
        self._ensure_entry(src)
        entry = self.threat_scores[src]

        target = arp_layer.dst_ip
        if target not in entry['arp_targets']:
            entry['arp_targets'].add(target)
            # normal hosts resolve a handful of peers; only sweeping scores
            if len(entry['arp_targets']) > ARP_FREE_TARGETS:
                entry['score'] += ARP_TARGET_WEIGHT
                logger.debug("ARP sweep from %s (%d targets) | score=%d",
                             src, len(entry['arp_targets']), entry['score'])
        self._check_threshold(src)

    def _add_port(self, src, port):
        entry = self.threat_scores[src]
        if port not in entry['ports']:
            entry['ports'].add(port)
            entry['score'] += SCAN_WEIGHT
            logger.info("New port %d probed by %s | score=%d",
                        port, src, entry['score'])

    def _check_rate(self, src):
        entry = self.threat_scores[src]
        now = time.time()
        entry['pkt_count'] += 1
        elapsed = now - entry['window_start']
        if elapsed >= 1.0:
            rate = entry['pkt_count'] / elapsed
            if rate > RATE_LIMIT:
                entry['score'] += HIGH_RATE_WEIGHT
                logger.warning("High rate %.1f pkt/s from %s | score=%d",
                               rate, src, entry['score'])
            entry['pkt_count'] = 0
            entry['window_start'] = now

    def _maybe_decay(self, src):
        entry = self.threat_scores[src]
        now = time.time()
        if now - entry['last_seen'] > DECAY_INTERVAL:
            entry['score'] = max(0, entry['score'] - DECAY_AMOUNT)
        entry['last_seen'] = now

    def _check_threshold(self, src):
        """
        Fire when the score crosses the threshold.

        detect_ts is stamped HERE, at the moment detection actually
        happens, and threaded down to the mutation module. The proposal
        defines Response Time = t_trigger - t_detection, but nothing was
        ever recording t_detection, so the reported figure was really
        t_install - t_trigger: the next segment of the path, not the one
        specified. Passing the timestamp lets all three segments be
        measured separately instead of conflated.

        The third argument is positional; MTDTrigger.on_threat_detected
        declares it with a default, so an older callback that takes only
        two arguments is not broken by this.
        """
        entry = self.threat_scores[src]
        if entry['score'] >= THREAT_THRESHOLD:
            detect_ts = time.time()
            logger.warning("THREAT THRESHOLD REACHED for %s (score=%d) - signalling MTD",
                           src, entry['score'])
            self._log_event(src, entry['score'], detect_ts)
            entry['score'] = 0
            entry['ports'] = set()
            entry['arp_targets'] = set()
            if self.mutation_callback:
                self.mutation_callback(src, THREAT_THRESHOLD, detect_ts)

    # -- Utilities -------------------------------------------------------------

    def _ensure_entry(self, src):
        if src not in self.threat_scores:
            self.threat_scores[src] = {
                'score':        0,
                'ports':        set(),
                'arp_targets':  set(),
                'last_seen':    time.time(),
                'pkt_count':    0,
                'window_start': time.time()
            }

    def _log_event(self, src, score, detect_ts=None):
        # wall_ts is the high-resolution companion to timestamp. strftime
        # only resolves to the second, which is useless for a measurement
        # whose whole range is a couple of seconds.
        with open(LOG_FILE, 'a') as f:
            f.write(json.dumps({
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'wall_ts':   round(detect_ts if detect_ts else time.time(), 4),
                'src_ip':    src,
                'score':     score,
                'event':     'MUTATION_TRIGGERED'
            }) + '\n')

    def get_score(self, ip):
        return self.threat_scores.get(ip, {}).get('score', 0)
