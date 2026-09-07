#!/usr/bin/env python3
"""
sdn_monitor.py
--------------
Controlador Ryu (OpenFlow 1.3) que combina:
  1) Una lógica de conmutación L2 de tipo "learning switch",
     implementada en el controlador, que instala reglas de flujo granulares
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

(normalmente no se necesita ejecutar esto directamente: se usa run_01_dataset.py
en la raíz del proyecto, ver EJECUCION.md)
"""

import csv
import os
import sys
import time
from datetime import datetime

# Red de seguridad: ver la misma nota en topology.py/traffic_generator.py.
# Sin esto, "import config" depende enteramente de que "pip install -e ."
# se haya ejecutado correctamente en el venv.
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
# previa. Una resolución ARP legítima responde en milisegundos; 5s da
# margen de sobra para retrasos de la red emulada sin llegar a tapar un
# ARP gratuito (que no tiene NINGUNA petición previa, ni reciente ni
# antigua). Ver self.recent_arp_requests.
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
        # flow_key -> (packet_count, byte_count, timestamp)
        # Guarda la lectura del ciclo anterior para calcular tasas diferenciales (pps y bps)
        self.prev_stats = {}
        # flow_key -> (packet_count, byte_count) 
        # Compensación para el primer paquete de un flujo: el paquete que desencadena el 
        # PacketIn no incrementa los contadores del FlowStats devuelto por el switch.
        self.pending_offsets = {}
        # flow_key -> flags TCP (entero, bitmask) del PRIMER paquete del
        # flujo -es el único momento en que el controlador ve el paquete
        # completo, no solo el match agregado del FlowStats-. Señal útil
        # para distinguir, p.ej., una sonda ACK suelta (solo ACK, nunca
        # visto como primer paquete de una conexión legítima) de tráfico
        # normal. No se hace pop() como con pending_offsets: el valor
        # debe seguir disponible en CADA sondeo mientras el flujo viva,
        # no solo en el primero.
        self.pending_tcp_flags = {}
        # ip -> mac, la PRIMERA vez que se vio esa IP -nunca se
        # sobrescribe a propósito, ni siquiera si llega un valor
        # distinto después (eso sería justo lo que un ataque de
        # spoofing intenta conseguir: que confiemos en la última
        # afirmación, no en la primera). Es la "verdad" de referencia
        # para detectar spoofing: comprobar si la MAC declarada de una
        # IP coincide con la que se vio la primera vez. NO se limpia en
        # los vaciados de tablas (_flush_all_flows) a propósito -a
        # diferencia de mac_to_port, que es estado de conmutación
        # transitorio, esto es identidad de host, que no cambia durante
        # toda la tirada-.
        self.ip_to_mac = {}
        # Se intenta cargar de forma diferida (no en __init__): el
        # controlador arranca ANTES que topology.py escriba
        # HOST_IDENTITY_FILE (el archivo no existe todavía en este
        # punto). Ver _try_load_host_identities().
        self._host_identities_loaded = False
        # flow_key -> 1 (consistente) / 0 (inconsistente, posible
        # spoofing), calculado en el momento del packet_in contra
        # ip_to_mac. Mismo patrón que pending_tcp_flags: no se hace
        # pop(), debe seguir disponible en cada sondeo mientras el
        # flujo viva.
        self.pending_ip_mac_consistent = {}
        # IP consultada -> instante de la última PETICIÓN ARP por esa IP.
        # Sirve para detectar RESPUESTAS ARP NO SOLICITADAS ("ARP
        # gratuito"): en el funcionamiento normal, una respuesta ARP
        # ("is-at") solo aparece después de que alguien haya preguntado
        # por esa IP. El envenenamiento de caché ARP consiste justo en
        # mandar respuestas que NADIE pidió, para que las víctimas
        # actualicen su tabla con una MAC falsa -es el heurístico
        # estándar de detección de ARP spoofing-.
        # Confirmado en los datos: spoofing tiene un 84% de respuestas
        # ARP frente al 49-59% de las demás clases.
        self.recent_arp_requests = {}
        # flow_key -> 1 (respuesta no solicitada) / 0 (solicitada).
        # Mismo patrón que pending_tcp_flags: sin pop(), debe seguir
        # disponible en cada sondeo mientras el flujo viva.
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
        """Inicializa LABEL_FILE con "warmup" al arrancar el controlador.
        
        Previene etiquetar el arranque con valores de ejecuciones anteriores
        interrumpidas y permite aislar el tráfico repetitivo de comprobación 
        inicial (pingAll) de la clase de tráfico "normal" real.
        """
        try:
            with open(LABEL_FILE, "w") as f:
                f.write("warmup,0")
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
        """Devuelve (label, phase_id, actores) de la fase actual.

        LABEL_FILE tiene el formato "label,phase_id,ip1|ip2|..." -el id y
        los actores los escribe set_label() en el generador-. El id permite
        distinguir fases CONSECUTIVAS DEL MISMO TIPO (que si no se
        fusionarían en un solo grupo para GroupKFold); los actores
        permiten etiquetar como ataque SOLO los flujos implicados, en vez
        de todo el tráfico que coincida en el tiempo (ver
        _label_for_flow). Se aceptan los formatos antiguos (solo "label",
        o "label,phase_id") por compatibilidad.
        """
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
        """Etiqueta de UNA fila concreta dentro de una fase de ataque.

        Devuelve la etiqueta del ataque solo si el flujo involucra a algún
        actor del ataque (atacante, víctima o identidad suplantada);
        "normal" en caso contrario.

        Motivo: antes se etiquetaba TODO el tráfico que ocurriera durante
        una fase de ataque con la etiqueta de esa fase -pero un escaneo lo
        lanza UN host, y en esas fases aparecen ~12 hosts origen distintos:
        la mayoría de filas eran tráfico legítimo de fondo con etiqueta de
        ataque-. Esas etiquetas erróneas eran ruido puro e impedían separar
        las clases: medido sobre datos reales, corregirlo sube el F1 de
        0.60 a 0.70 sin tocar nada más. Es además el criterio estándar en
        datasets de detección de intrusiones (CICIDS y similares etiquetan
        por pareja origen/destino del ataque, no por franja horaria).

        Si no hay actores (fase "normal", o CSV/generador antiguo sin ese
        dato), se conserva la etiqueta de la fase tal cual.
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
        """Carga (una sola vez, en cuanto esté disponible) las parejas
        IP/MAC reales de los hosts desde HOST_IDENTITY_FILE -escrito por
        topology.py tras levantar la red, con host.IP()/host.MAC()-.

        Se llama al principio de _packet_in_handler porque el
        controlador arranca ANTES que topology.py escriba el archivo
        -no se puede hacer en __init__, el archivo no existiría
        todavía-. Una vez cargado (self._host_identities_loaded=True),
        no vuelve a intentarlo -es barato comprobar el flag, no hace
        falta más-.
        """
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
            # No crítico: si falla, ip_to_mac se sigue "aprendiendo" del
            # primer paquete que llegue -el comportamiento previo, sin
            # la mejora, pero sin romper nada-.
            self.logger.warning(
                "No se pudieron cargar identidades de host desde %s: %s",
                config.HOST_IDENTITY_FILE, e,
            )

    def _check_arp_solicited(self, arp_pkt):
        """Para paquetes ARP, distingue respuestas SOLICITADAS de las que no.

        Devuelve:
          - None  si es una PETICIÓN (no aplica; además la registra para
            poder comprobar las respuestas que lleguen después).
          - 0     si es una respuesta que SÍ contesta a una petición
            reciente (comportamiento normal).
          - 1     si es una respuesta que NADIE pidió ("ARP gratuito"):
            la firma clásica del envenenamiento de caché ARP.

        Nota honesta: el ARP gratuito también existe de forma legítima
        (un host anunciando un cambio de IP/MAC al arrancar), así que
        esta señal por sí sola no prueba un ataque -es un indicio, y el
        modelo la combina con el resto de características-.
        """
        now = time.time()
        # Limpiar peticiones caducadas para que el diccionario no crezca
        # sin límite en tiradas largas.
        if len(self.recent_arp_requests) > 1000:
            self.recent_arp_requests = {
                ip: t for ip, t in self.recent_arp_requests.items()
                if now - t <= ARP_REQUEST_TTL
            }

        # Valores numéricos (1=petición, 2=respuesta) en vez de las
        # constantes de Ryu: son los códigos estándar del protocolo ARP
        # y coinciden con lo que aparece en la columna arp_opcode del
        # CSV ya generado, así que no dependemos de cómo se llamen las
        # constantes en la versión de Ryu instalada.
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
        """Genera una tupla identificadora única (DNI) para cada flujo.
        
        Usa get_field para extraer de forma homogénea tanto diccionarios (PacketIn) 
        como objetos OFPMatch (FlowStats), incluyendo campos L2/L3/L4 y ARP para 
        evitar colisiones de contadores entre conversaciones distintas.
        """
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
        """Maneja paquetes desconocidos (table-miss): aprende direcciones MAC,
        construye reglas granulares (L2-L4/ARP) y reenvía el paquete inicial.
        """
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
            # arp_pkt.src_mac (campo "sender hardware address" del propio
            # ARP) en vez de "src" (eth_src de la trama) -es el campo que
            # el spoofing de ARP manipula directamente, más preciso aquí-.
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
        """Consulta periódicamente las estadísticas de flujo a todos los switches activos."""
        while True:
            for dp in list(self.datapaths.values()):
                self._request_flow_stats(dp)
            hub.sleep(POLL_INTERVAL)

    # ---------------------------------------------------------- #
    # Vigilancia de cambios de fase (label) y limpieza de flujos
    # ---------------------------------------------------------- #
    def _label_watch_loop(self):
        """Vigila cambios de etiqueta o peticiones de purga para vaciar las tablas 
        de flujo del switch y prevenir la contaminación entre fases.
        """
        while True:
            current_label, current_phase, _ = self._read_current_label()
            # Comparar por (label, phase_id): así también se detecta el
            # cambio entre dos fases CONSECUTIVAS DEL MISMO TIPO (p.ej.
            # scanning -> scanning), que antes pasaban desapercibidas y
            # no vaciaban las tablas -dejando que los flujos de la fase
            # anterior contaminaran la siguiente-.
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
        """Elimina todos los flujos instalados en los switches y reinicia los contadores internos."""
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
        self.pending_tcp_flags.clear()
        self.pending_ip_mac_consistent.clear()
        self.pending_arp_unsolicited.clear()
        # NOTA: self.ip_to_mac NO se limpia aquí a propósito -es
        # identidad de host (ver comentario en __init__), no estado de
        # conmutación transitorio. Debe persistir toda la tirada.

    def _request_flow_stats(self, datapath):
        """Envía una petición de estadísticas de flujo (OFPFlowStatsRequest) al switch."""
        parser = datapath.ofproto_parser
        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _flow_stats_reply_handler(self, ev):
        """Procesa las estadísticas recibidas, calcula características derivadas (pps/bps),
        aplica compensaciones de primer paquete y escribe las muestras en el CSV.
        """
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

            # Flags TCP del primer paquete del flujo (guardados en
            # _packet_in_handler, ver pending_tcp_flags). NO se hace
            # pop(): debe seguir disponible en cada sondeo mientras el
            # flujo viva, no solo en el primero. "" si no es TCP (ARP,
            # ICMP, UDP) o si el flujo ya existía antes de arrancar el
            # controlador -mismo criterio que el resto de campos "no
            # aplica" del proyecto-.
            tcp_flags = self.pending_tcp_flags.get(flow_key, "")

            # Consistencia IP<->MAC (spoofing), mismo criterio que
            # tcp_flags: "" si no se pudo calcular (p.ej. flujo previo
            # al arranque del controlador).
            ip_mac_consistent = self.pending_ip_mac_consistent.get(flow_key, "")

            # Respuesta ARP no solicitada (ARP gratuito): "" si el flujo
            # no es una respuesta ARP (mismo criterio que el resto de
            # columnas "no aplica").
            arp_unsolicited_reply = self.pending_arp_unsolicited.get(flow_key, "")

            # Sumar el offset del paquete inicial consumido durante el PacketIn
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
                # Estimación inicial o recuperación tras expiración/reinstalación de flujo
                flow_age = stat.duration_sec + stat.duration_nsec / 1e9
                if flow_age > 0:
                    pps = packet_count / flow_age
                    bps = byte_count / flow_age
                else:
                    pps = 0.0
                    bps = 0.0
            self.prev_stats[flow_key] = (packet_count, byte_count, now)

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
