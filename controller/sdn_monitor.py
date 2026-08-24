#!/usr/bin/env python3
"""
sdn_monitor.py
--------------
Controlador Ryu (OpenFlow 1.3) que combina:
  1) Un switch L2 "aprendiz" que instala reglas de flujo granulares
     (por IP origen/destino, protocolo, puertos, o campos ARP) para que
     cada "conversación" de red genere entradas de flujo diferenciadas.
  2) Un monitor periódico que consulta OFPFlowStatsRequest a cada switch
     conectado, calcula características derivadas (pps, bps, tamaño medio
     de paquete, etc.) y guarda cada fila en un CSV listo para ML.

La etiqueta (label) de cada fila se lee de un fichero de texto compartido
(LABEL_FILE) que el script de generación de tráfico en Mininet va
actualizando según la fase de tráfico activa (normal / scanning /
spoofing / ddos). Así el controlador no necesita saber nada del
generador de tráfico: solo lee "cuál es la fase actual".

Ejecución:
    ryu-manager sdn_monitor.py
"""

import csv
import os
import sys
import time
from datetime import datetime

# Permite "import config" independientemente del cwd desde el que
# ryu-manager cargue este fichero.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib import hub
from ryu.lib.packet import packet, ethernet, ether_types, ipv4, tcp, udp, arp

# ------------------------------------------------------------------ #
# CONFIGURACIÓN - centralizada en config.py (raíz del proyecto)
# ------------------------------------------------------------------ #
LABEL_FILE = config.LABEL_FILE
CSV_FILE = config.CSV_FILE
POLL_INTERVAL = config.POLL_INTERVAL
FLOW_IDLE_TIMEOUT = config.FLOW_IDLE_TIMEOUT
FLOW_HARD_TIMEOUT = config.FLOW_HARD_TIMEOUT

CSV_HEADERS = [
    "timestamp", "dpid",
    "eth_src", "eth_dst", "eth_type",
    "ip_src", "ip_dst", "ip_proto",
    "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port",
    "arp_opcode", "arp_spa", "arp_tpa", "arp_sha",
    "duration_sec", "duration_nsec",
    "idle_timeout", "hard_timeout",
    "packet_count", "byte_count",
    "packet_count_per_second", "byte_count_per_second",
    "avg_packet_size",
    "flow_count_per_dpid",
    "label",
]


class SDNFlowMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFlowMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # key -> (packet_count, byte_count, timestamp) para calcular tasas (pps/bps)
        self.prev_stats = {}
        self._init_csv()
        self.monitor_thread = hub.spawn(self._monitor_loop)

    # ---------------------------------------------------------- #
    # CSV
    # ---------------------------------------------------------- #
    def _init_csv(self):
        write_header = not os.path.exists(CSV_FILE)
        self.csv_fp = open(CSV_FILE, "a", newline="")
        self.csv_writer = csv.writer(self.csv_fp)
        if write_header:
            self.csv_writer.writerow(CSV_HEADERS)
            self.csv_fp.flush()

    def _read_current_label(self):
        try:
            with open(LABEL_FILE, "r") as f:
                return f.read().strip() or "normal"
        except FileNotFoundError:
            return "normal"

    # ---------------------------------------------------------- #
    # Gestión de datapaths (switches conectados)
    # ---------------------------------------------------------- #
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.info("Switch conectado: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.info("Switch desconectado: %016x", datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        # regla de table-miss: todo lo desconocido va al controlador
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(datapath, 0, match, actions, idle_timeout=0, hard_timeout=0)

    def _add_flow(self, datapath, priority, match, actions, idle_timeout=0, hard_timeout=0):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(
            datapath=datapath, priority=priority, match=match, instructions=inst,
            idle_timeout=idle_timeout, hard_timeout=hard_timeout,
        )
        datapath.send_msg(mod)

    # ---------------------------------------------------------- #
    # Switch L2 con reglas granulares (para que cada "conversación"
    # de red -normal, escaneo, ddos, spoofing- genere flujos propios)
    # ---------------------------------------------------------- #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        dpid = datapath.id
        in_port = msg.match["in_port"]

        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]

        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        src, dst = eth.src, eth.dst
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][src] = in_port
        out_port = self.mac_to_port[dpid].get(dst, ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match_fields = {"in_port": in_port, "eth_src": src, "eth_dst": dst}

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_IP
            match_fields["ipv4_src"] = ip_pkt.src
            match_fields["ipv4_dst"] = ip_pkt.dst
            match_fields["ip_proto"] = ip_pkt.proto

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port
            elif udp_pkt:
                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port

        elif arp_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_ARP
            match_fields["arp_spa"] = arp_pkt.src_ip
            match_fields["arp_tpa"] = arp_pkt.dst_ip
            match_fields["arp_sha"] = arp_pkt.src_mac
            match_fields["arp_op"] = arp_pkt.opcode

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(**match_fields)
            self._add_flow(
                datapath, 1, match, actions,
                idle_timeout=FLOW_IDLE_TIMEOUT, hard_timeout=FLOW_HARD_TIMEOUT,
            )

        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data

        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id,
            in_port=in_port, actions=actions, data=data,
        )
        datapath.send_msg(out)

    # ---------------------------------------------------------- #
    # Monitor periódico
    # ---------------------------------------------------------- #
    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(POLL_INTERVAL)

    def _request_flow_stats(self, datapath):
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        label = self._read_current_label()
        now = time.time()
        flow_count = len(body)

        for stat in body:
            match = stat.match

            eth_src = match.get("eth_src", "")
            eth_dst = match.get("eth_dst", "")
            eth_type = match.get("eth_type", "")
            ip_src = match.get("ipv4_src", "")
            ip_dst = match.get("ipv4_dst", "")
            ip_proto = match.get("ip_proto", "")
            tcp_src = match.get("tcp_src", "")
            tcp_dst = match.get("tcp_dst", "")
            udp_src = match.get("udp_src", "")
            udp_dst = match.get("udp_dst", "")
            arp_op = match.get("arp_op", "")
            arp_spa = match.get("arp_spa", "")
            arp_tpa = match.get("arp_tpa", "")
            arp_sha = match.get("arp_sha", "")

            packet_count = stat.packet_count
            byte_count = stat.byte_count

            flow_key = (
                dpid, eth_src, eth_dst, ip_src, ip_dst, ip_proto,
                tcp_src, tcp_dst, udp_src, udp_dst,
            )
            prev = self.prev_stats.get(flow_key)
            if prev:
                prev_packets, prev_bytes, prev_time = prev
                dt = max(now - prev_time, 1e-6)
                pps = max((packet_count - prev_packets) / dt, 0)
                bps = max((byte_count - prev_bytes) / dt, 0)
            else:
                pps = 0.0
                bps = 0.0
            self.prev_stats[flow_key] = (packet_count, byte_count, now)

            avg_pkt_size = (byte_count / packet_count) if packet_count > 0 else 0

            row = [
                datetime.now().isoformat(), dpid,
                eth_src, eth_dst, eth_type,
                ip_src, ip_dst, ip_proto,
                tcp_src, tcp_dst, udp_src, udp_dst,
                arp_op, arp_spa, arp_tpa, arp_sha,
                stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout,
                packet_count, byte_count,
                round(pps, 2), round(bps, 2), round(avg_pkt_size, 2),
                flow_count, label,
            ]
            self.csv_writer.writerow(row)
        self.csv_fp.flush()
