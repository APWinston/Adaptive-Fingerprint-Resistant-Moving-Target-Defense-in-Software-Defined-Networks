"""
Threat Scoring Engine
=====================
Monitors incoming OpenFlow PacketIn events and assigns a threat score
to each source IP based on traffic behaviour (scan rate, port diversity,
ARP probing). When the score exceeds THREAT_THRESHOLD, it signals the
MTD trigger to fire a network mutation.

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

# ── Configuration ────────────────────────────────────────────────────────────
THREAT_THRESHOLD    = 50      # Score at which MTD mutation fires
SCAN_WEIGHT         = 10      # Points per unique port probed
ARP_PROBE_WEIGHT    = 5       # Points per ARP probe
HIGH_RATE_WEIGHT    = 15      # Points when pkt rate exceeds RATE_LIMIT
RATE_LIMIT          = 20      # Packets/sec threshold for high-rate penalty
DECAY_INTERVAL      = 10      # Seconds before score starts decaying
DECAY_AMOUNT        = 5       # Points removed per decay cycle
LOG_FILE            = "logs/threat_scores.log"
# ─────────────────────────────────────────────────────────────────────────────

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [ThreatEngine] %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

os.makedirs("logs", exist_ok=True)


class ThreatScoringEngine(app_manager.RyuApp):
    """
    Passive traffic monitor that builds per-IP threat scores.
    Other Ryu apps can read self.threat_scores[ip] at any time.
    """

    def __init__(self, *args, **kwargs):
        super(ThreatScoringEngine, self).__init__(*args, **kwargs)

        # { src_ip: { 'score': int, 'ports': set, 'last_seen': float,
        #             'pkt_count': int, 'window_start': float } }
        self.threat_scores = {}

        # Callback registered by MTD trigger: called when threshold exceeded
        self.mutation_callback = None

        logger.info("Threat Scoring Engine initialised. Threshold=%d", THREAT_THRESHOLD)

    # ── Event Handler ─────────────────────────────────────────────────────────

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        pkt       = packet.Packet(ev.msg.data)
        eth_layer = pkt.get_protocol(ethernet.ethernet)
        if eth_layer is None:
            return

        ip_layer  = pkt.get_protocol(ipv4.ipv4)
        arp_layer = pkt.get_protocol(arp.arp)

        if ip_layer:
            self._process_ip(pkt, ip_layer)
        elif arp_layer:
            self._process_arp(arp_layer)

    # ── Processing Helpers ────────────────────────────────────────────────────

    def _process_ip(self, pkt, ip_layer):
        src = ip_layer.src
        self._ensure_entry(src)

        tcp_layer = pkt.get_protocol(tcp.tcp)
        udp_layer = pkt.get_protocol(udp.udp)

        # Port scan detection
        if tcp_layer:
            self._add_port(src, tcp_layer.dst_port)
        elif udp_layer:
            self._add_port(src, udp_layer.dst_port)

        # High packet-rate detection
        self._check_rate(src)
        self._maybe_decay(src)
        self._check_threshold(src)

    def _process_arp(self, arp_layer):
        src = arp_layer.src_ip
        self._ensure_entry(src)
        # ARP probing (who-has with unknown target) raises score
        self.threat_scores[src]['score'] += ARP_PROBE_WEIGHT
        logger.debug("ARP probe from %s | score=%d", src,
                     self.threat_scores[src]['score'])
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
        now   = time.time()
        entry['pkt_count'] += 1
        elapsed = now - entry['window_start']
        if elapsed >= 1.0:
            rate = entry['pkt_count'] / elapsed
            if rate > RATE_LIMIT:
                entry['score'] += HIGH_RATE_WEIGHT
                logger.warning("High rate %.1f pkt/s from %s | score=%d",
                               rate, src, entry['score'])
            entry['pkt_count']    = 0
            entry['window_start'] = now

    def _maybe_decay(self, src):
        """Gradually reduce score for IPs that have gone quiet."""
        entry = self.threat_scores[src]
        now   = time.time()
        if now - entry['last_seen'] > DECAY_INTERVAL:
            entry['score'] = max(0, entry['score'] - DECAY_AMOUNT)
        entry['last_seen'] = now

    def _check_threshold(self, src):
        score = self.threat_scores[src]['score']
        if score >= THREAT_THRESHOLD:
            logger.warning("THREAT THRESHOLD REACHED for %s (score=%d) — signalling MTD",
                           src, score)
            self._log_event(src, score)
            # Reset score to avoid repeated triggers
            self.threat_scores[src]['score'] = 0
            self.threat_scores[src]['ports'] = set()
            if self.mutation_callback:
                self.mutation_callback(src, score)

    # ── Utilities ─────────────────────────────────────────────────────────────

    def _ensure_entry(self, src):
        if src not in self.threat_scores:
            self.threat_scores[src] = {
                'score':        0,
                'ports':        set(),
                'last_seen':    time.time(),
                'pkt_count':    0,
                'window_start': time.time()
            }

    def _log_event(self, src, score):
        with open(LOG_FILE, 'a') as f:
            entry = {
                'timestamp': time.strftime('%Y-%m-%d %H:%M:%S'),
                'src_ip':    src,
                'score':     score,
                'event':     'MUTATION_TRIGGERED'
            }
            f.write(json.dumps(entry) + '\n')

    def get_score(self, ip):
        """Public API: return current threat score for an IP."""
        return self.threat_scores.get(ip, {}).get('score', 0)
