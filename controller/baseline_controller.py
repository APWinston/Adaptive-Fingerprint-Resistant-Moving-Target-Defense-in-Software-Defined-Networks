"""
Baseline MTD Controller (Fixed-Interval Mode)
===============================================
Identical to mtd_controller.py but runs in BASELINE mode —
mutations fire on a fixed timer regardless of traffic.

This is used ONLY for comparison/evaluation against the adaptive system.

Run with:
  ryu-manager controller/baseline_controller.py

Group 46 - Adaptive Fingerprint-Resistant MTD in SDN
"""

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.packet import packet, ethernet, ipv4, arp
import logging
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from controller.threat_engine   import ThreatScoringEngine
from controller.mtd_trigger     import MTDTrigger
from controller.mutation_module import MutationModule

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [BASELINE] %(levelname)s - %(message)s"
)
logger = logging.getLogger(__name__)

MTD_MODE = 'baseline'   # Fixed-interval mode for comparison


class BaselineController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(BaselineController, self).__init__(*args, **kwargs)

        self.datapaths   = {}
        self.mac_to_port = {}

        self.threat_engine   = ThreatScoringEngine()
        self.mutation_module = MutationModule(self.datapaths)
        self.mtd_trigger     = MTDTrigger(self.mutation_module, mode=MTD_MODE)

        # In baseline mode, trigger fires automatically — no callback needed
        logger.info("Baseline Controller started — fixed interval every %ds",
                    30)

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofp      = datapath.ofproto
        parser   = datapath.ofproto_parser

        self.datapaths[datapath.id] = datapath
        logger.info("Switch connected: dpid=%s", datapath.id)

        match   = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                          ofp.OFPCML_NO_BUFFER)]
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

        if dst in self.mac_to_port[dpid]:
            out_port = self.mac_to_port[dpid][dst]
        else:
            out_port = ofp.OFPP_FLOOD

        actions = [parser.OFPActionOutput(out_port)]

        if out_port != ofp.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=dst, eth_src=src)
            if msg.buffer_id != ofp.OFP_NO_BUFFER:
                self._add_flow(datapath, 1, match, actions, msg.buffer_id)
                return
            else:
                self._add_flow(datapath, 1, match, actions)

        data = None
        if msg.buffer_id == ofp.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data
        )
        datapath.send_msg(out)

    def _add_flow(self, datapath, priority, match, actions,
                  buffer_id=None, idle_timeout=0, hard_timeout=0):
        ofp    = datapath.ofproto
        parser = datapath.ofproto_parser
        inst   = [parser.OFPInstructionActions(ofp.OFPIT_APPLY_ACTIONS, actions)]

        kwargs = dict(datapath=datapath, priority=priority,
                      match=match, instructions=inst,
                      idle_timeout=idle_timeout, hard_timeout=hard_timeout)
        if buffer_id and buffer_id != ofp.OFP_NO_BUFFER:
            kwargs['buffer_id'] = buffer_id

        mod = parser.OFPFlowMod(**kwargs)
        datapath.send_msg(mod)
