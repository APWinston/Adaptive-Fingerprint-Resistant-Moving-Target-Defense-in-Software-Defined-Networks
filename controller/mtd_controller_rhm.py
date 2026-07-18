"""
MTD Controller (RHM pipeline)
=============================
One controller for BOTH arms of the RDR experiment. The mode is chosen by
environment variable rather than by duplicating the file:

    ryu-manager controller/mtd_controller_rhm.py                        # adaptive
    MTD_MODE=adaptive_floor ryu-manager controller/mtd_controller_rhm.py
    MTD_MODE=baseline ryu-manager controller/mtd_controller_rhm.py

Keeping the two arms in one file matters for the comparison. The original
project has mtd_controller.py and baseline_controller.py as near-identical
twins, and any fix applied to one and forgotten on the other becomes a
silent confound: a difference in results that is really a difference in
code. Here the ONLY difference between the arms is the mutation policy -
threat-driven versus fixed-timer - and the stagger flag that goes with it.

PIPELINE (see mutation_module_rhm.py for the full rationale)

    TABLE 0  source translation      real -> virtual
    TABLE 1  destination translation virtual -> real, plus the real-IP shield
    TABLE 2  L2 / microflow forwarding

The controller owns TABLE 2 and the table-miss entries. The mutation
module owns tables 0 and 1.

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

from controller.threat_engine       import ThreatScoringEngine
from controller.mtd_trigger         import MTDTrigger
from controller.mutation_module_rhm import (
    MutationModuleRHM, TABLE_SRC, TABLE_DST, TABLE_FWD, is_virtual_ip)

MTD_MODE = os.environ.get("MTD_MODE", "adaptive").lower()

logging.basicConfig(
    level=logging.INFO,
    format="%%(asctime)s [%s-RHM] %%(levelname)s - %%(message)s" % MTD_MODE.upper())
logger = logging.getLogger(__name__)

ATTACKER_IP = os.environ.get("ATTACKER_IP", "10.0.0.99")
ETH_IPV4    = 0x0800


class MTDControllerRHM(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(MTDControllerRHM, self).__init__(*args, **kwargs)

        self.datapaths   = {}
        self.mac_to_port = {}
        self.ip_to_mac   = {}

        # Both adaptive arms stagger; only the baseline installs
        # simultaneously. Staggering is part of the treatment under test,
        # so it must be identical across the two adaptive arms or the floor
        # would be confounded with it.
        stagger = MTD_MODE.startswith("adaptive")
        self.threat_engine   = ThreatScoringEngine()
        self.mutation_module = MutationModuleRHM(self.datapaths, stagger=stagger)
        self.mtd_trigger     = MTDTrigger(self.mutation_module, mode=MTD_MODE)

        # Threat scoring drives mutation only in the adaptive arm. In the
        # baseline arm the engine still runs and still logs, so both arms
        # see identical scan traffic and identical CPU from scoring - but
        # the trigger is the fixed timer inside MTDTrigger.
        if MTD_MODE.startswith("adaptive"):
            self.threat_engine.mutation_callback = self.mtd_trigger.on_threat_detected

        logger.info("Controller started | mode=%s | stagger=%s | attacker=%s",
                    MTD_MODE.upper(), stagger, ATTACKER_IP)

    # -- Switch bring-up -------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        logger.info("Switch connected: dpid=%s", datapath.id)

        # Table-miss chain. Tables 0 and 1 fall THROUGH to the next table
        # rather than punting to the controller: a packet from an
        # unregistered source, or to an address that is not a live virtual
        # one, must still reach the forwarding table to be handled or
        # dropped there. Only table 2 punts.
        self._goto_miss(datapath, TABLE_SRC, TABLE_DST)
        self._goto_miss(datapath, TABLE_DST, TABLE_FWD)
        self._add_flow(datapath, TABLE_FWD, 0, parser.OFPMatch(),
                       [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)])

        # A switch that joins late must receive the mapping that already
        # exists, or traffic crossing it would be shielded with no
        # translation behind the shield.
        self.mutation_module.install_all_on(datapath)

    def _goto_miss(self, datapath, table_id, next_table):
        parser = datapath.ofproto_parser
        datapath.send_msg(parser.OFPFlowMod(
            datapath=datapath, table_id=table_id, priority=0,
            match=parser.OFPMatch(),
            instructions=[parser.OFPInstructionGotoTable(next_table)]))

    # -- Packet in -------------------------------------------------------------

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def packet_in_handler(self, ev):
        msg      = ev.msg
        datapath = msg.datapath
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser
        in_port  = msg.match['in_port']
        dpid     = datapath.id

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        if eth is None:
            return

        src, dst = eth.src, eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port

        ip_layer  = pkt.get_protocol(ipv4.ipv4)
        arp_layer = pkt.get_protocol(arp.arp)

        # ---- Learning -----------------------------------------------------
        # Packets arriving here have already traversed table 0, so an IPv4
        # source is the host's VIRTUAL address once that host is
        # registered. ARP is not translated (the rules match eth_type
        # 0x0800), so ARP is the reliable source of real IP -> MAC
        # bindings and of new-host discovery.
        if arp_layer:
            self.ip_to_mac[arp_layer.src_ip] = src
            if arp_layer.src_ip != ATTACKER_IP:
                # dpid pins the host to its edge switch. First report wins:
                # a host's own switch always packet_ins before any switch
                # the frame is later flooded to.
                self.mutation_module.register_host(arp_layer.src_ip, dpid)

        if ip_layer and not is_virtual_ip(ip_layer.src):
            # An untranslated IPv4 source means the host is not registered
            # yet - register it, and record the binding.
            self.ip_to_mac[ip_layer.src] = src
            if ip_layer.src != ATTACKER_IP:
                self.mutation_module.register_host(ip_layer.src, dpid)

        # ---- Threat scoring -----------------------------------------------
        # BEFORE the ARP proxy, not after. The proxy returns early for any
        # request aimed at a live virtual address, and scoring downstream of
        # that early return means those requests are never scored at all -
        # so an attacker sweeping the address space would have its hits on
        # real hosts silently excluded from its own threat score, while only
        # its misses counted. Detection must see every packet the switch
        # sends up, whatever the controller then decides to do with it.
        self.threat_engine.packet_in_handler(ev)

        # ---- ARP proxy for virtual addresses ------------------------------
        if arp_layer and self._proxy_arp(datapath, in_port, eth, arp_layer):
            return

        # ---- Forwarding (TABLE 2) -----------------------------------------
        out_port = self.mac_to_port[dpid].get(dst, ofp.OFPP_FLOOD)
        actions  = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            tcp_layer = pkt.get_protocol(tcp.tcp)
            udp_layer = pkt.get_protocol(udp.udp)
            # Per-port microflow rules keep each newly probed port a table
            # miss, so a port sweep stays visible to the threat engine
            # instead of being absorbed by one broad MAC-level rule.
            if ip_layer and tcp_layer:
                match = parser.OFPMatch(in_port=in_port, eth_type=ETH_IPV4,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=6, tcp_dst=tcp_layer.dst_port)
            elif ip_layer and udp_layer:
                match = parser.OFPMatch(in_port=in_port, eth_type=ETH_IPV4,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=17, udp_dst=udp_layer.dst_port)
            elif ip_layer:
                match = parser.OFPMatch(in_port=in_port, eth_type=ETH_IPV4,
                                        ipv4_src=ip_layer.src, ipv4_dst=ip_layer.dst,
                                        ip_proto=ip_layer.proto)
            else:
                match = parser.OFPMatch(in_port=in_port, eth_dst=dst,
                                        eth_src=src, eth_type=eth.ethertype)

            # idle_timeout keeps table 2 from filling with microflows whose
            # virtual addresses have since been mutated away.
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(datapath, TABLE_FWD, 1, match, actions,
                               buffer_id=msg.buffer_id, idle_timeout=30)
                return
            self._add_flow(datapath, TABLE_FWD, 1, match, actions, idle_timeout=30)

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data))

    # -- ARP proxy -------------------------------------------------------------

    def _proxy_arp(self, datapath, in_port, eth_pkt, arp_pkt):
        """
        Answer ARP for LIVE virtual addresses only.

        No host owns a virtual address, so without this nobody replies and
        the address is unusable. Answering only for addresses in the
        CURRENT mapping is what makes RDR measurable: after a mutation the
        attacker's cached virtual address is no longer answered for, and a
        probe to it finds no translation rule either.

        Returns True if the request was consumed here.
        """
        if arp_pkt.opcode != arp.ARP_REQUEST:
            return False

        target = arp_pkt.dst_ip
        real   = self.mutation_module.get_real_ip(target)
        if real == target:
            return False               # not a live virtual address

        mac = self.ip_to_mac.get(real)
        if mac is None:
            return False               # host not learned yet

        reply = packet.Packet()
        reply.add_protocol(ethernet.ethernet(
            ethertype=eth_pkt.ethertype, dst=eth_pkt.src, src=mac))
        reply.add_protocol(arp.arp(
            opcode=arp.ARP_REPLY, src_mac=mac, src_ip=target,
            dst_mac=arp_pkt.src_mac, dst_ip=arp_pkt.src_ip))
        reply.serialize()

        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        datapath.send_msg(parser.OFPPacketOut(
            datapath=datapath, buffer_id=ofp.OFP_NO_BUFFER,
            in_port=ofp.OFPP_CONTROLLER,
            actions=[parser.OFPActionOutput(in_port)],
            data=reply.data))
        return True

    # -- Helper ----------------------------------------------------------------

    def _add_flow(self, datapath, table_id, priority, match, actions,
                  buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofp, parser = datapath.ofproto, datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]
        kwargs = dict(datapath=datapath, table_id=table_id, priority=priority,
                      match=match, instructions=inst,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id
        datapath.send_msg(parser.OFPFlowMod(**kwargs))
