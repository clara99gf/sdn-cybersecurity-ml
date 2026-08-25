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
FLUSH_REQUEST_FILE = config.FLUSH_REQUEST_FILE
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
        # key -> (paquetes, bytes) "invisibles" para OVS: el paquete que
        # dispara el PacketIn y la instalación de la regla NUNCA se
        # cuenta en las estadísticas de esa regla (ver _packet_in_handler)
        self.pending_offsets = {}
        self._last_label = None
        self._last_flush_request = None
        self._reset_label_file()
        self._reset_flush_request_file()
        self._init_csv()
        self.monitor_thread = hub.spawn(self._monitor_loop)
        self.label_watch_thread = hub.spawn(self._label_watch_loop)

    # ---------------------------------------------------------- #
    # CSV
    # ---------------------------------------------------------- #
    def _reset_flush_request_file(self):
        """Ver _label_watch_loop: el generador de tráfico puede pedir un
        vaciado de tablas AHORA MISMO (sin esperar a un cambio de
        etiqueta) escribiendo un timestamp nuevo aquí -lo usa cuando una
        fase supera MAX_ROWS_PER_PHASE a mitad de fase, para no seguir
        muestreando flujos ya creados durante el resto de su vida útil."""
        try:
            with open(FLUSH_REQUEST_FILE, "w") as f:
                f.write("0")
        except OSError:
            pass

    def _read_flush_request(self):
        try:
            with open(FLUSH_REQUEST_FILE, "r") as f:
                return f.read().strip()
        except (FileNotFoundError, OSError):
            return "0"

    def _reset_label_file(self):
        """Si una ejecución anterior se interrumpió (Ctrl+C) a mitad de una
        fase, runtime/current_label.txt se queda con esa etiqueta puesta.
        Sin este reset, TODO el tráfico de arranque (pingAll) de la
        ejecución NUEVA -antes de que el generador llame a set_label() por
        primera vez- se etiquetaría con la etiqueta vieja (p.ej. 'ddos'),
        que es exactamente lo que explicaba filas ARP de pingAll con
        flow_count muy alto apareciendo como 'ddos'.

        Se usa "warmup" (no "normal"): el pingAll() inicial es tráfico
        benigno de verdad, pero muy homogéneo (240 pares de hosts, 1-2
        paquetes cada uno) y puede acabar siendo la mayoría de las filas
        "normal" si la primera fase elegida al azar también es normal,
        diluyendo la variedad que sí aporta normal_traffic() (ping/iperf
        TCP/UDP). Con una etiqueta propia, decides tú en el preprocesado
        si la incluyes como tráfico normal más, o la filtras."""
        try:
            with open(LABEL_FILE, "w") as f:
                f.write("warmup")
        except OSError:
            pass

    def _init_csv(self):
        if config.RESET_DATASET_ON_START and os.path.exists(CSV_FILE):
            if config.ARCHIVE_PREVIOUS_DATASET:
                timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
                backup = CSV_FILE.replace(".csv", f"_{timestamp}.csv")
                os.rename(CSV_FILE, backup)
                self.logger.info("Dataset anterior archivado en: %s", backup)
            else:
                os.remove(CSV_FILE)
                self.logger.info("Dataset anterior eliminado, empezando limpio.")

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
        self._install_table_miss(datapath)

    def _install_table_miss(self, datapath):
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

    def _flow_key(self, dpid, get_field):
        """Construye la clave de un flujo de forma consistente, tanto desde
        match_fields (dict, en el packet_in) como desde stat.match (OFPMatch,
        en la respuesta de estadísticas) -ambos exponen .get(campo, defecto).
        Incluye los campos ARP para que dos conversaciones ARP distintas
        entre el mismo par de MACs (spa/tpa/op distintos) no compartan
        clave -si no, sus contadores/offsets pendientes se mezclarían-."""
        return (
            dpid,
            get_field("eth_src", ""), get_field("eth_dst", ""),
            get_field("ipv4_src", ""), get_field("ipv4_dst", ""),
            get_field("ip_proto", ""),
            get_field("tcp_src", ""), get_field("tcp_dst", ""),
            get_field("udp_src", ""), get_field("udp_dst", ""),
            get_field("arp_spa", ""), get_field("arp_tpa", ""),
            get_field("arp_op", ""),
        )

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
            # El paquete que dispara ESTE PacketIn (y la instalación de la
            # regla) nunca lo cuenta el propio switch en las estadísticas
            # de esa regla -la regla no existía todavía cuando llegó-. Lo
            # apuntamos aquí para sumarlo cuando leamos las stats (ver
            # _flow_stats_reply_handler), en vez de perderlo como un
            # falso "0 paquetes / 0 bytes".
            flow_key = self._flow_key(dpid, match_fields.get)
            extra_p, extra_b = self.pending_offsets.get(flow_key, (0, 0))
            self.pending_offsets[flow_key] = (extra_p + 1, extra_b + msg.total_len)

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

    # ---------------------------------------------------------- #
    # Vigilancia de cambios de fase (label) y limpieza de flujos
    # ---------------------------------------------------------- #
    # PROBLEMA que esto resuelve: OFPFlowStatsRequest devuelve TODOS los
    # flujos activos en el switch, no solo los que generó la fase actual.
    # Como una entrada de flujo puede seguir viva hasta FLOW_HARD_TIMEOUT
    # segundos después de creada, si la fase cambia justo antes de que
    # expire (p.ej. de "scanning" a "spoofing"), esa fila queda etiquetada
    # con la fase nueva aunque el tráfico real sea de la fase anterior
    # ("contaminación" de etiquetas en las fronteras entre fases). Por eso
    # vaciamos activamente la tabla de flujos en cuanto detectamos que
    # LABEL_FILE ha cambiado, en vez de esperar a que expiren solas.
    #
    # Además, un vaciado disparado SOLO por cambios de etiqueta no basta
    # para MAX_ROWS_PER_PHASE: el generador solo puede detectar que una
    # fase se ha pasado de filas DESPUÉS de que el controlador ya las
    # haya escrito (el CSV solo crece en cada sondeo), y aunque deje de
    # lanzar tráfico nuevo en cuanto lo detecta, los flujos YA CREADOS
    # siguen vivos hasta su hard_timeout y se siguen muestreando -sumando
    # filas de más- mientras tanto. Por eso también se vigila
    # FLUSH_REQUEST_FILE: el generador puede pedir un vaciado inmediato
    # en el momento exacto en que detecta el desbordamiento, sin esperar
    # a que la fase termine y cambie la etiqueta.
    def _label_watch_loop(self):
        while True:
            current = self._read_current_label()
            flush_request = self._read_flush_request()
            need_flush = False

            if current != self._last_label:
                if self._last_label is not None:
                    self.logger.info(
                        "Cambio de fase detectado: %s -> %s. Vaciando tablas de flujo.",
                        self._last_label, current,
                    )
                    need_flush = True
                self._last_label = current

            if flush_request != self._last_flush_request:
                if self._last_flush_request is not None:
                    self.logger.info(
                        "Vaciado de flujos solicitado por el generador (tope de fase superado)."
                    )
                    need_flush = True
                self._last_flush_request = flush_request

            if need_flush:
                self._flush_all_flows()
            hub.sleep(0.3)

    def _flush_all_flows(self):
        for dp in list(self.datapaths.values()):
            ofproto = dp.ofproto
            parser = dp.ofproto_parser
            match = parser.OFPMatch()
            mod = parser.OFPFlowMod(
                datapath=dp, command=ofproto.OFPFC_DELETE,
                out_port=ofproto.OFPP_ANY, out_group=ofproto.OFPG_ANY,
                match=match, priority=0, instructions=[],
            )
            dp.send_msg(mod)
            # OFPFC_DELETE con match comodín borra también la regla de
            # table-miss (prioridad 0); la reinstalamos para seguir
            # recibiendo PacketIn de los paquetes nuevos de la siguiente fase.
            self._install_table_miss(dp)
        # limpiamos también el histórico de mac_to_port, tasas y offsets
        # pendientes, para no "arrastrar" contadores/aprendizaje de la
        # fase anterior
        self.mac_to_port.clear()
        self.prev_stats.clear()
        self.pending_offsets.clear()

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

        # La regla de table-miss (prioridad 0, match comodín) es un
        # contador AGREGADO del switch -cuántos paquetes desconocidos ha
        # visto en total-, no un flujo/conversación real: no tiene
        # eth_src/ip_src/etc. propios. La excluimos para no mezclar una
        # fila "agregada" (con esos campos vacíos) con las de flujos
        # individuales.
        flow_stats = [s for s in body if s.priority != 0]
        flow_count = len(flow_stats)

        # --------------------------------------------------------- #
        # Diagnóstico: si flow_count se dispara, esto nos dice si son
        # sobre todo flujos ARP o IP, y sobre todo si son "recién
        # instalados" (duration_sec/nsec muy bajo) -lo que indicaría
        # que se están reinstalando en cada sondeo en vez de persistir
        # como una única entrada estable-.
        n_arp = sum(1 for s in flow_stats if s.match.get("eth_type") == ether_types.ETH_TYPE_ARP)
        n_ip = sum(1 for s in flow_stats if s.match.get("eth_type") == ether_types.ETH_TYPE_IP)
        n_fresh = sum(1 for s in flow_stats if s.duration_sec == 0)
        self.logger.info(
            "[poll] dpid=%016x label=%s flows=%d (arp=%d ip=%d recien_instalados=%d)",
            dpid, label, flow_count, n_arp, n_ip, n_fresh,
        )

        for stat in flow_stats:
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

            flow_key = self._flow_key(dpid, match.get)

            # Sumamos el paquete "invisible" que instaló esta regla (si lo
            # hay y todavía no se había consumido en un poll anterior).
            extra_p, extra_b = self.pending_offsets.pop(flow_key, (0, 0))
            packet_count = stat.packet_count + extra_p
            byte_count = stat.byte_count + extra_b

            prev = self.prev_stats.get(flow_key)
            if prev and packet_count >= prev[0]:
                prev_packets, prev_bytes, prev_time = prev
                dt = max(now - prev_time, 1e-6)
                pps = max((packet_count - prev_packets) / dt, 0)
                bps = max((byte_count - prev_bytes) / dt, 0)
            else:
                # O bien es la primera vez que vemos este flujo, o bien
                # había una muestra previa pero packet_count es MENOR que
                # la que teníamos guardada -señal inequívoca de que el
                # flujo anterior con esta misma clave expiró (idle/hard
                # timeout) y se ha reinstalado desde cero-. Comparar
                # contra la muestra vieja daría una resta negativa que se
                # recortaría a 0 de forma incorrecta (esto explicaba
                # bastantes de las tasas a 0.0 que no deberían serlo). En
                # cualquiera de los dos casos usamos la duración propia
                # que reporta el switch (duration_sec + duration_nsec)
                # como mejor estimación disponible.
                flow_age = stat.duration_sec + stat.duration_nsec / 1e9
                if flow_age > 0:
                    pps = packet_count / flow_age
                    bps = byte_count / flow_age
                else:
                    pps = 0.0
                    bps = 0.0
            self.prev_stats[flow_key] = (packet_count, byte_count, now)

            avg_pkt_size = (byte_count / packet_count) if packet_count > 0 else 0

            if label == "warmup" and not config.WRITE_WARMUP_ROWS:
                continue

            row = [
                datetime.now().isoformat(timespec="microseconds"), dpid,
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
