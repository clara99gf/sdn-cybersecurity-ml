#!/usr/bin/env python3
"""
controller/sdn_monitor.py
-------------------------
Controlador Ryu (OpenFlow 1.3) de la fase 1. Hace dos cosas:
 
  1) Conmutación L2 con reglas de flujo granulares (por IP, protocolo,
     puertos o campos ARP), de modo que cada conversación de red genera
     entradas de flujo distintas y separables.
  2) Un monitor que cada POLL_INTERVAL pide las estadísticas de flujo a
     los switches, calcula características derivadas (pps, bps, tamaño
     medio, consistencia IP/MAC, ARP no solicitado...) y escribe una fila
     por flujo en el CSV del dataset.
 
La etiqueta de cada fila se lee de LABEL_FILE, que el generador de
tráfico actualiza según la fase activa. Así el controlador no necesita
conocer el generador: solo lee la fase actual y sus actores.
 
Lo lanza run_01_dataset.py; no se ejecuta directamente.
"""

import csv
import os
import sys
import time
from datetime import datetime

# Permite "import config" sin depender de la instalación editable.
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
# CONFIGURACIÓN - Centralizada en config.py 
# ------------------------------------------------------------------ #
LABEL_FILE = config.LABEL_FILE
FLUSH_REQUEST_FILE = config.FLUSH_REQUEST_FILE
CSV_FILE = config.CSV_FILE
POLL_INTERVAL = config.POLL_INTERVAL
FLOW_IDLE_TIMEOUT = config.FLOW_IDLE_TIMEOUT
# Margen para considerar que una respuesta ARP contesta a una petición
# previa. Una resolución legítima responde en milisegundos; 5s cubre los
# retrasos de la red emulada sin llegar a tapar un ARP gratuito, que no
# tiene ninguna petición previa. Ver self.recent_arp_requests.
ARP_REQUEST_TTL = 5.0
FLOW_HARD_TIMEOUT = config.FLOW_HARD_TIMEOUT

CSV_HEADERS = [
    "timestamp", "dpid",
    "eth_src", "eth_dst", "eth_type",
    "ip_src", "ip_dst", "ip_proto",
    "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port",
    "tcp_flags",
    "ip_mac_consistent",
    "arp_unsolicited_reply",
    "arp_opcode", "arp_spa", "arp_tpa", "arp_sha",
    "duration_sec", "duration_nsec",
    "idle_timeout", "hard_timeout",
    "packet_count", "byte_count",
    "packet_count_per_second", "byte_count_per_second",
    "avg_packet_size",
    "flow_count_per_dpid",
    "phase_id",
    "label",
]


class SDNFlowMonitor(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNFlowMonitor, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # flow_key -> (packet_count, byte_count, timestamp, flow_age).
        # Lectura anterior de cada flujo, para las tasas diferenciales
        # (pps, bps). flow_age detecta la reinstalación de un flujo: si su
        # duración va hacia atrás, el switch reinició los contadores.
        self.prev_stats = {}
        # flow_key -> (packet_count, byte_count) pendientes de aplicar. El
        # paquete que dispara el PacketIn no lo cuenta el FlowStats del
        # switch, así que se compensa aquí.
        self.pending_offsets = {}
        # flow_key -> (packet_count, byte_count) de compensación ya
        # aplicados. La compensación debe mantenerse en cada sondeo
        # mientras el flujo viva; si solo se aplicara en el primero, el
        # contador acumulado bajaría en el segundo, lo cual es imposible
        # en OpenFlow. Se descarta al reinstalarse el flujo.
        self.applied_offsets = {}
        # flow_key -> flags TCP del primer paquete (bitmask). Es el único
        # momento en que el controlador ve el paquete completo. Útil para
        # distinguir, p.ej., una sonda ACK del tráfico normal. Como las
        # tres estructuras "pending_" siguientes, se conserva en cada
        # sondeo mientras el flujo viva (sin pop).
        self.pending_tcp_flags = {}
        # ip -> mac vista la PRIMERA vez, verdad de referencia contra la
        # que se detecta el spoofing. Nunca se sobrescribe (aceptar la
        # última afirmación es justo lo que busca un ataque) ni se limpia
        # en los vaciados: es identidad de host, no estado transitorio.
        self.ip_to_mac = {}
        # ip_to_mac se siembra de HOST_IDENTITY_FILE de forma diferida, no
        # en __init__: el controlador arranca antes de que topology.py
        # escriba ese fichero. Ver _try_load_host_identities.
        self._host_identities_loaded = False
        # flow_key -> 1/0 según si la MAC declarada para la IP coincide
        # con ip_to_mac. Calculado en el packet_in, conservado por sondeo.
        self.pending_ip_mac_consistent = {}
        # ip consultada -> instante de la última PETICIÓN ARP. Una
        # respuesta ARP ("is-at") normal solo llega tras una petición; una
        # que nadie pidió ("ARP gratuito") es la firma del envenenamiento
        # de caché ARP.
        self.recent_arp_requests = {}
        # flow_key -> 1/0 según si la respuesta ARP fue no solicitada.
        # Conservado por sondeo, como el resto de "pending_".
        self.pending_arp_unsolicited = {}
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
        """Limpia el archivo FLUSH_REQUEST_FILE escribiendo "0" para indicar
        que no hay peticiones de purga de flujos pendientes."""
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
        """Deja LABEL_FILE en "warmup" al arrancar, para no heredar la
        etiqueta de una ejecución anterior y para descartar el tráfico del
        pingAll inicial."""
        try:
            with open(LABEL_FILE, "w") as f:
                f.write("warmup,0")
        except OSError:
            pass

    def _init_csv(self):
        """Abre el CSV del dataset para escritura. Según config, archiva o
        borra el anterior, y escribe la cabecera si el fichero es nuevo."""
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
        """Devuelve (label, phase_id, actores) de la fase actual, leídos de
        LABEL_FILE ("label,phase_id,ip1|ip2|..."). El phase_id distingue
        fases consecutivas del mismo tipo; los actores permiten etiquetar
        como ataque solo los flujos implicados (ver _label_for_flow)."""
        try:
            with open(LABEL_FILE, "r") as f:
                raw = f.read().strip()
        except FileNotFoundError:
            return "normal", "0", frozenset()
        if not raw:
            return "normal", "0", frozenset()
        parts = raw.split(",")
        label = parts[0].strip() or "normal"
        phase_id = parts[1].strip() if len(parts) > 1 and parts[1].strip() else "0"
        actors = frozenset(
            ip for ip in (parts[2].split("|") if len(parts) > 2 else []) if ip
        )
        return label, phase_id, actors

    @staticmethod
    def _label_for_flow(phase_label, actors, ip_src, ip_dst, arp_spa, arp_tpa):
        """Etiqueta de una fila concreta dentro de una fase de ataque.
 
        Devuelve la etiqueta del ataque solo si el flujo involucra a algún
        actor (atacante, víctima o identidad suplantada), y "normal" en
        caso contrario, de modo que el tráfico de fondo simultáneo al
        ataque no se etiqueta como ataque. Es el criterio estándar en
        datasets del área (CICIDS y similares etiquetan por pareja
        origen/destino del ataque, no por franja temporal).
 
        Sin actores (fase normal) se conserva la
        etiqueta de la fase tal cual.
        """
        if not actors or phase_label in ("normal", "warmup"):
            return phase_label
        for ip in (ip_src, ip_dst, arp_spa, arp_tpa):
            if ip and ip in actors:
                return phase_label
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
        # Regla de table-miss: todo lo desconocido va al controlador
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

    def _try_load_host_identities(self):
        """Siembra ip_to_mac desde HOST_IDENTITY_FILE la primera vez que el
        fichero está disponible. Se llama desde _packet_in_handler, no
        desde __init__, porque el controlador arranca antes de que
        topology.py escriba el fichero. Si falla, ip_to_mac se aprende del
        tráfico como alternativa."""
        if self._host_identities_loaded:
            return
        if not os.path.exists(config.HOST_IDENTITY_FILE):
            return
        try:
            with open(config.HOST_IDENTITY_FILE) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ip, mac = line.split(",")
                    self.ip_to_mac[ip] = mac.lower()
            self._host_identities_loaded = True
            self.logger.info(
                "[+] Identidades de host cargadas desde %s (%d hosts) -para "
                "detección de spoofing con verdad de referencia desde el "
                "arranque-", config.HOST_IDENTITY_FILE, len(self.ip_to_mac),
            )
        except Exception as e:
            # No crítico: si falla, ip_to_mac se aprende del primer
            # paquete de cada IP.
            self.logger.warning(
                "No se pudieron cargar identidades de host desde %s: %s",
                config.HOST_IDENTITY_FILE, e,
            )

    def _check_arp_solicited(self, arp_pkt):
        """Para paquetes ARP, distingue respuestas solicitadas de las que no.
 
        Devuelve None si es una petición (y la registra para comprobar las
        respuestas posteriores), 0 si es una respuesta a una petición
        reciente, y 1 si es una respuesta que nadie pidió ("ARP gratuito"),
        firma del envenenamiento de caché ARP. El ARP gratuito también
        existe de forma legítima, así que es un indicio, no una prueba: el
        modelo lo combina con el resto de características.
        """
        now = time.time()
        # Limpiar peticiones caducadas para que el diccionario no crezca
        # sin límite en tiradas largas.
        if len(self.recent_arp_requests) > 1000:
            self.recent_arp_requests = {
                ip: t for ip, t in self.recent_arp_requests.items()
                if now - t <= ARP_REQUEST_TTL
            }

        # Se usan los códigos numéricos del protocolo (1=petición,
        # 2=respuesta), que coinciden con la columna arp_opcode del CSV y
        # no dependen de cómo se llamen las constantes en esta versión de
        # Ryu.
        if arp_pkt.opcode == 1:
            # Alguien pregunta "¿quién tiene dst_ip?" -> anotarlo.
            self.recent_arp_requests[arp_pkt.dst_ip] = now
            return None

        if arp_pkt.opcode == 2:
            # "src_ip está en src_mac": ¿lo había preguntado alguien?
            t = self.recent_arp_requests.get(arp_pkt.src_ip)
            return 0 if (t is not None and now - t <= ARP_REQUEST_TTL) else 1

        return None

    def _check_ip_mac(self, claimed_ip, claimed_mac):
        """Comprueba (y aprende, si es la primera vez) la relación IP->MAC.
 
        Devuelve 1 si la MAC declarada coincide con la primera vista
        para esa IP (o es la primera vez que se ve, nada que
        contradecir), 0 si NO coincide -señal de spoofing-. Ver
        self.ip_to_mac para el porqué de no sobrescribir nunca.
        Comparación insensible a mayúsculas/minúsculas -Mininet y Ryu
        podrían representar la misma MAC con distinto casing-.
        """
        claimed_mac = claimed_mac.lower()
        known_mac = self.ip_to_mac.get(claimed_ip)
        if known_mac is None:
            self.ip_to_mac[claimed_ip] = claimed_mac
            return 1
        return 1 if known_mac == claimed_mac else 0

    def _flow_key(self, dpid, get_field):
        """Tupla que identifica un flujo de forma única, combinando dpid y
        campos L2/L3/L4/ARP. get_field abstrae el origen (dict del PacketIn
        u OFPMatch del FlowStats) para construirla igual en los dos casos."""
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
    # de red -normal, scanning, ddos, spoofing- genere flujos propios)
    # ---------------------------------------------------------- #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        """Procesa un paquete desconocido: aprende su MAC, calcula las
        señales del primer paquete (flags TCP, consistencia IP/MAC, ARP no
        solicitado), instala una regla granular para el flujo y reenvía el
        paquete."""
        self._try_load_host_identities()

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
        tcp_flags = None
        ip_mac_consistent = None
        arp_unsolicited = None

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)

        if ip_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_IP
            match_fields["ipv4_src"] = ip_pkt.src
            match_fields["ipv4_dst"] = ip_pkt.dst
            match_fields["ip_proto"] = ip_pkt.proto
            ip_mac_consistent = self._check_ip_mac(ip_pkt.src, src)

            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port
                tcp_flags = tcp_pkt.bits  # flags del PRIMER paquete (ver pending_tcp_flags)
                if config.DEBUG_TCP_FLAGS:
                    self.logger.info(
                        "[debug-tcp] %s:%s -> %s:%s flags=%d (bin=%s)",
                        ip_pkt.src, tcp_pkt.src_port, ip_pkt.dst, tcp_pkt.dst_port,
                        tcp_flags, format(tcp_flags, "08b"),
                    )
            elif udp_pkt:
                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port
            elif config.DEBUG_TCP_FLAGS and ip_pkt.proto != 1:
                # IP pero ni TCP ni UDP reconocidos (y no ICMP, que es
                # esperado y frecuente) -por si algún paquete se estuviera
                # viendo como otra cosa inesperada-.
                self.logger.info(
                    "[debug-tcp] IP no-TCP/UDP: %s -> %s, ip_proto=%d (paquete no reconocido como tcp_pkt)",
                    ip_pkt.src, ip_pkt.dst, ip_pkt.proto,
                )

        elif arp_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_ARP
            match_fields["arp_spa"] = arp_pkt.src_ip
            match_fields["arp_tpa"] = arp_pkt.dst_ip
            match_fields["arp_sha"] = arp_pkt.src_mac
            match_fields["arp_op"] = arp_pkt.opcode
            # arp_pkt.src_mac (el campo del propio ARP) en vez del eth_src
            # de la trama: es el campo que el ARP spoofing manipula.
            ip_mac_consistent = self._check_ip_mac(arp_pkt.src_ip, arp_pkt.src_mac)
            arp_unsolicited = self._check_arp_solicited(arp_pkt)

        if out_port != ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(**match_fields)
            self._add_flow(
                datapath, 1, match, actions,
                idle_timeout=FLOW_IDLE_TIMEOUT, hard_timeout=FLOW_HARD_TIMEOUT,
            )
            # Registrar offset para no perder el recuento del primer paquete
            flow_key = self._flow_key(dpid, match_fields.get)
            extra_p, extra_b = self.pending_offsets.get(flow_key, (0, 0))
            self.pending_offsets[flow_key] = (extra_p + 1, extra_b + msg.total_len)
            if tcp_flags is not None:
                self.pending_tcp_flags[flow_key] = tcp_flags
            if ip_mac_consistent is not None:
                self.pending_ip_mac_consistent[flow_key] = ip_mac_consistent
            if arp_unsolicited is not None:
                self.pending_arp_unsolicited[flow_key] = arp_unsolicited

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
        """Pide las estadísticas de flujo a todos los switches cada
        POLL_INTERVAL segundos."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(POLL_INTERVAL)

    # ---------------------------------------------------------- #
    # Vigilancia de cambios de fase (label) y limpieza de flujos
    # ---------------------------------------------------------- #
    def _label_watch_loop(self):
        """Vacía las tablas de flujo cuando cambia la fase o el generador
        pide una purga, para que los flujos de una fase no contaminen la
        siguiente."""
        while True:
            current_label, current_phase, _ = self._read_current_label()
            # Se compara por (label, phase_id): así también se detecta el
            # cambio entre dos fases consecutivas del mismo tipo (p.ej.
            # scanning -> scanning), que si no dejarían sus flujos activos
            # contaminando la siguiente fase.
            current = (current_label, current_phase)
            flush_request = self._read_flush_request()
            need_flush = False

            if current != self._last_label:
                if self._last_label is not None:
                    self.logger.info(
                        "Cambio de fase detectado: %s -> %s. Vaciando tablas de flujo.",
                        self._last_label[0], current_label,
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
        """Borra todos los flujos de los switches, reinstala la regla
        table-miss y reinicia el estado interno por flujo."""
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
            # Reinstalar la regla table-miss (eliminada por el match comodín)
            self._install_table_miss(dp)
        # Limpiar registros históricos para evitar arrastrar métricas a la nueva fase
        self.mac_to_port.clear()
        self.prev_stats.clear()
        self.pending_offsets.clear()
        self.applied_offsets.clear()
        self.pending_tcp_flags.clear()
        self.pending_ip_mac_consistent.clear()
        self.pending_arp_unsolicited.clear()
        # ip_to_mac NO se limpia aquí a propósito: es identidad de host
        # (ver __init__), no estado de conmutación, y persiste toda la
        # tirada.

    def _request_flow_stats(self, datapath):
        """Envía una petición de estadísticas de flujo (OFPFlowStatsRequest) al switch."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Por cada flujo activo: aplica la compensación del primer paquete,
        calcula las tasas (pps, bps), determina la etiqueta por actores y
        escribe la fila en el CSV."""
        body = ev.msg.body
        dpid = ev.msg.datapath.id
        phase_label, phase_id, actors = self._read_current_label()
        now = time.time()

        # Filtrar la regla de table-miss (prioridad 0) para procesar solo flujos individuales
        flow_stats = [s for s in body if s.priority != 0]
        flow_count = len(flow_stats)

        # Registro de diagnóstico sobre la composición de los flujos activos
        n_arp = sum(1 for s in flow_stats if s.match.get("eth_type") == ether_types.ETH_TYPE_ARP)
        n_ip = sum(1 for s in flow_stats if s.match.get("eth_type") == ether_types.ETH_TYPE_IP)
        n_fresh = sum(1 for s in flow_stats if s.duration_sec == 0)
        self.logger.info(
            "[poll] dpid=%016x label=%s flows=%d (arp=%d ip=%d recien_instalados=%d)",
            dpid, phase_label, flow_count, n_arp, n_ip, n_fresh,
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

            # Flags TCP del primer paquete (ver pending_tcp_flags). "" si
            # el flujo no es TCP o ya existía antes de arrancar el
            # controlador, mismo criterio que el resto de campos "no aplica".
            tcp_flags = self.pending_tcp_flags.get(flow_key, "")

            # Consistencia IP<->MAC (spoofing); "" si no se pudo calcular.
            ip_mac_consistent = self.pending_ip_mac_consistent.get(flow_key, "")

            # Respuesta ARP no solicitada; "" si el flujo no es respuesta ARP.
            arp_unsolicited_reply = self.pending_arp_unsolicited.get(flow_key, "")

            # Compensación del primer paquete (ver applied_offsets):
            flow_age = stat.duration_sec + stat.duration_nsec / 1e9
            prev = self.prev_stats.get(flow_key)
            if prev is not None and flow_age + 1e-3 < prev[3]:
                # La duración va hacia atrás: el switch borró el flujo
                # (idle/hard timeout) y lo ha reinstalado con los
                # contadores a cero. Ni la compensación acumulada ni la
                # lectura anterior sirven ya para este flujo.
                self.applied_offsets.pop(flow_key, None)
                prev = None
            new_p, new_b = self.pending_offsets.pop(flow_key, (0, 0))
            off_p, off_b = self.applied_offsets.get(flow_key, (0, 0))
            off_p, off_b = off_p + new_p, off_b + new_b
            self.applied_offsets[flow_key] = (off_p, off_b)
            packet_count = stat.packet_count + off_p
            byte_count = stat.byte_count + off_b

            if prev is not None and packet_count >= prev[0]:
                prev_packets, prev_bytes, prev_time, _ = prev
                dt = max(now - prev_time, 1e-6)
                pps = max((packet_count - prev_packets) / dt, 0)
                bps = max((byte_count - prev_bytes) / dt, 0)
            else:
                # Estimación inicial o recuperación tras expiración/reinstalación de flujo
                if flow_age > 0:
                    pps = packet_count / flow_age
                    bps = byte_count / flow_age
                else:
                    pps = 0.0
                    bps = 0.0
            self.prev_stats[flow_key] = (packet_count, byte_count, now, flow_age)

            avg_pkt_size = (byte_count / packet_count) if packet_count > 0 else 0

            # Etiqueta POR FLUJO: la de la fase solo si este flujo
            # involucra a los actores del ataque (ver _label_for_flow).
            label = self._label_for_flow(
                phase_label, actors, ip_src, ip_dst, arp_spa, arp_tpa,
            )

            if label == "warmup" and not config.WRITE_WARMUP_ROWS:
                continue

            row = [
                datetime.now().isoformat(timespec="microseconds"), dpid,
                eth_src, eth_dst, eth_type,
                ip_src, ip_dst, ip_proto,
                tcp_src, tcp_dst, udp_src, udp_dst,
                tcp_flags,
                ip_mac_consistent,
                arp_unsolicited_reply,
                arp_op, arp_spa, arp_tpa, arp_sha,
                stat.duration_sec, stat.duration_nsec,
                stat.idle_timeout, stat.hard_timeout,
                packet_count, byte_count,
                round(pps, 2), round(bps, 2), round(avg_pkt_size, 2),
                flow_count, phase_id, label,
            ]
            self.csv_writer.writerow(row)
        self.csv_fp.flush()
