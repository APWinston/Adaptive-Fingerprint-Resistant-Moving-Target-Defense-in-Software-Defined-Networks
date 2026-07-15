"""
Main MTD Controller (Adaptive)
==============================
Entry point Ryu app. Wires together:
  - ThreatScoringEngine  (detects reconnaissance)
  - MTDTrigger           (decides when to mutate)
  - MutationModule       (performs staggered mutation)

Run with:
  ryu-manager controller/mtd_controller.py

FIX: hosts are now REGISTERED with the mutation module as they are
learned from traffic. Without this the mutation module's ip_mapping stays
empty, every mutation generates an empty mapping, and no flow rules are
ever installed - the system logs mutations while doing nothing.

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp, tcp, udp
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.threat_engine   import ThreatScoringEngine
from controller.mtd_trigger     import MTDTrigger
from controller.mutation_module import MutationModule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [MTDController] %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

MTD_MODE = 'adaptive'
ATTACKER_IP = '10.0.0.99'   # not mutated; it is the adversary, not a protected host


class MTDController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDController, self).__init__(*args, **kwargs)

        self.datapaths   = {}
        self.mac_to_port = {}
        self.ip_to_mac   = {}   # real IP -> MAC, used by the ARP proxy

        self.threat_engine   = ThreatScoringEngine()
        self.mutation_module = MutationModule(self.datapaths, stagger=True,
                                              port_resolver=self._resolve_port)
        self.mtd_trigger     = MTDTrigger(self.mutation_module, mode=MTD_MODE)

        self.threat_engine.mutation_callback = self.mtd_trigger.on_threat_detected

        logger.info("MTD Controller started in %s mode", MTD_MODE.upper())

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        logger.info("Switch connected: dpid=%s", datapath.id)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER, ofp.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions)

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        dst  = eth.dst
        src  = eth.src
        dpid = datapath.id

        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        # ---- REGISTER HOSTS FOR MUTATION (the missing link) --------------
        # Every protected host seen on the network is added to the mutation
        # module's mapping, so that a mutation actually has addresses to
        # remap and real flow rules to install.
        ip_layer  = pkt.get_protocol(ipv4.ipv4)
        arp_layer = pkt.get_protocol(arp.arp)

        # learn IP -> MAC so the ARP proxy can answer for virtual addresses
        if ip_layer:
            self.ip_to_mac[ip_layer.src] = src
        if arp_layer:
            self.ip_to_mac[arp_layer.src_ip] = src

        if ip_layer and ip_layer.src != ATTACKER_IP:
            self.mutation_module.add_host(ip_layer.src)
        if arp_layer and arp_layer.src_ip != ATTACKER_IP:
            self.mutation_module.add_host(arp_layer.src_ip)

        # answer ARP for virtual addresses before normal forwarding
        if arp_layer and self._proxy_arp(datapath, in_port, eth, arp_layer):
            return
        # ------------------------------------------------------------------

        # Threat scoring
        self.threat_engine.packet_in_handler(ev)

        # L2 forwarding
        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        # ---- FORWARDING RULE GRANULARITY -------------------------------
        # A MAC-based rule (in_port, eth_dst, eth_src) matches ALL traffic
        # between two hosts, so after the first packet the switch forwards
        # everything itself and the controller never sees the rest. A port
        # sweep would then be invisible to the Threat Scoring Engine.
        #
        # For TCP/UDP we therefore install a per-port microflow rule, so each
        # newly probed port is a genuine table miss and reaches the engine.
        # ICMP/ARP keep the cheaper MAC-based rule.
        if out_port != ofp.OFPP_FLOOD:
            tcp_layer = pkt.get_protocol(tcp.tcp)
            udp_layer = pkt.get_protocol(udp.udp)
            if ip_layer and tcp_layer:
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=6, tcp_dst=tcp_layer.dst_port)
            elif ip_layer and udp_layer:
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=17, udp_dst=udp_layer.dst_port)
            elif ip_layer:
                # ICMP and any other IP protocol. This MUST be pinned to
                # ip_proto: a rule matching only MAC addresses would also
                # match TCP, so a single ping would install a rule that
                # swallows every later port probe and hide the scan from
                # the Threat Scoring Engine entirely.
                match = parser.OFPMatch(in_port=in_port, eth_type=0x0800,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=ip_layer.proto)
            else:
                # ARP and non-IP traffic, pinned to its ethertype
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,
                                        eth_src=src, eth_type=eth.ethertype)

            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions,
                               msg.buffer_id, idle_timeout=30)
                return
            else:
                self._add_flow(datapath, 1, match, actions, idle_timeout=30)
        # ------------------------------------------------------------------

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data
        out = parser.OFPPacketOut(datapath=datapath, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        datapath.send_msg(out)


    # ---- ARP PROXY ---------------------------------------------------------
    def _resolve_port(self, dpid, real_ip):
        """Port on `dpid` that reaches `real_ip`, or None if not yet learned."""
        mac = self.ip_to_mac.get(real_ip)
        if mac is None:
            return None
        return self.mac_to_port.get(dpid, {}).get(mac)

    def _proxy_arp(self, datapath, in_port, eth_pkt, arp_pkt):
        """
        Answer ARP requests for virtual addresses.

        A virtual IP exists only inside the switch flow tables - no host owns
        it, so nobody replies when a peer asks "who has <virtual>?". Without
        this proxy the very first packet to a virtual address is never sent
        and the mutation appears to break the network.

        The controller replies on behalf of the real host, handing back that
        host's MAC, so the packet is sent and the switch's translation rule
        can rewrite the destination.

        Returns True if the request was handled here.
        """
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return False

        target = arp_pkt.dst_ip
        real   = self.mutation_module.get_real_ip(target)
        if real == target:
            return False                     # a real address; normal ARP applies

        mac = self.ip_to_mac.get(real)
        if mac is None:
            return False                     # host not learned yet

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=eth_pkt.ethertype, dst=eth_pkt.src, src=mac))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=mac, src_ip=target,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
        reply.serialize()

        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data))
        logger.info("ARP proxy: told %s that %s is at %s",
                    arp_pkt.src_ip, target, mac)
        return True
    # ------------------------------------------------------------------------

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, priority=priority, match=match,
                      instructions=inst, idle_timeout=idle_timeout,
                      hard_timeout=hard_timeout)
        if buffer_id and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))
