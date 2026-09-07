"""
sdn_defense.py
--------------
Controlador Ryu para la FASE DE DETECCIÓN Y MITIGACIÓN en vivo.

A diferencia de controller/sdn_monitor.py (que solo OBSERVA y escribe un
CSV etiquetado para entrenar), este controlador:

  1. Sondea las estadísticas de flujo igual que el monitor.
  2. Clasifica cada flujo EN VIVO con el modelo entrenado
     (controller/live_classifier.py), reproduciendo el mismo preprocesado.
  3. MITIGA: si un flujo se clasifica como ataque (ddos/scanning/
     spoofing), inyecta una regla OpenFlow (OFPFlowMod) de prioridad
     alta y acción DROP para bloquear ese tráfico.
  4. Registra métricas a un CSV de eventos (metrics/defense_events.csv):
     por cada flujo evaluado guarda su predicción, el tiempo de
     inferencia del modelo, la latencia del plano de control (desde que
     llega el EventOFPFlowStatsReply hasta que se envía el OFPFlowMod de
     mitigación) y si se aplicó DROP -para las gráficas del orquestador-.

El CPU del proceso Ryu se muestrea en un hilo aparte y también se
vuelca al CSV de eventos, para la gráfica de doble eje CPU vs latencia.

Uso (lo lanza run_03_defense.py; no suele ejecutarse a mano):
    ryu-manager controller/sdn_defense.py
"""
import csv
import os
import threading
import time
from datetime import datetime

import config
from controller.live_classifier import LiveClassifier

from ryu.base import app_manager
from ryu.controller import ofp_event
from ryu.controller.handler import (
    MAIN_DISPATCHER, DEAD_DISPATCHER, CONFIG_DISPATCHER, set_ev_cls,
)
from ryu.lib import hub
from ryu.lib.packet import (
    packet, ethernet, ether_types, ipv4, tcp, udp, arp,
)
from ryu.ofproto import ofproto_v1_3

try:
    import psutil
    _HAS_PSUTIL = True
except ImportError:
    _HAS_PSUTIL = False

POLL_INTERVAL = config.POLL_INTERVAL
FLOW_IDLE_TIMEOUT = config.FLOW_IDLE_TIMEOUT
FLOW_HARD_TIMEOUT = config.FLOW_HARD_TIMEOUT
ATTACK_CLASSES = {"ddos", "scanning", "spoofing"}
MITIGATION_PRIORITY = 100  # muy por encima de las reglas normales
ARP_REQUEST_TTL = 5.0      # ventana para "respuesta ARP solicitada" (ver sdn_monitor)

METRICS_DIR = os.path.join(config.PROJECT_ROOT, "metrics")
os.makedirs(METRICS_DIR, exist_ok=True)
EVENTS_CSV = os.path.join(METRICS_DIR, "defense_events.csv")

EVENT_HEADERS = [
    "timestamp", "event_type", "dpid", "src", "dst", "dst_port",
    "predicted_label", "inference_ms", "control_latency_ms",
    "mitigated", "pkt_rate", "distinct_ports", "distinct_sources",
    "ryu_cpu_percent",
]


class SDNDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        self.prev_stats = {}
        self.mitigated = set()   # flow_keys ya bloqueados (no repetir OFPFlowMod)
        # Estado para las 3 features que se calculan en el packet_in
        # (igual que en sdn_monitor.py): flags TCP del primer paquete,
        # consistencia IP/MAC (spoofing) y respuesta ARP no solicitada.
        # Se indexan por flow_key y se leen al llegar las estadísticas.
        self.pending_tcp_flags = {}
        self.pending_ip_mac_consistent = {}
        self.pending_arp_unsolicited = {}
        self.ip_to_mac = {}
        self.recent_arp_requests = {}
        # La carga de identidades se hace de forma DIFERIDA (no aquí): el
        # controlador arranca antes de que run_03_defense.py levante la
        # red y escriba host_identities.csv. Se intenta en cada packet_in
        # hasta que el archivo exista (igual que sdn_monitor.py).
        self._identities_loaded = False
        self.classifier = LiveClassifier()
        self.logger.info("[defense] Modelo de clasificación cargado.")

        self._proc = psutil.Process(os.getpid()) if _HAS_PSUTIL else None
        self._cpu = 0.0
        self._events = []
        self._events_lock = threading.Lock()
        self._init_events_csv()

        self.monitor_thread = hub.spawn(self._monitor_loop)
        if self._proc is not None:
            hub.spawn(self._cpu_loop)

    # ------------------------------------------------------------------ #
    # Registro de datapaths
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change(self, ev):
        dp = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            self.datapaths[dp.id] = dp
        elif ev.state == DEAD_DISPATCHER and dp.id in self.datapaths:
            del self.datapaths[dp.id]

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _features(self, ev):
        dp = ev.msg.datapath
        parser = dp.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, match, actions)
        self.logger.info("[defense] Switch conectado: %016x", dp.id)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        mod = parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                instructions=inst, idle_timeout=idle,
                                hard_timeout=hard)
        dp.send_msg(mod)

    # ------------------------------------------------------------------ #
    # Cálculo de las 3 features del packet_in (idéntico a sdn_monitor.py)
    # ------------------------------------------------------------------ #
    def _load_host_identities(self):
        """Siembra ip_to_mac con las identidades reales de los hosts
        (mismo mecanismo que sdn_monitor.py): así la detección de
        spoofing parte de la verdad desde el arranque en vez de tener
        que aprenderla del primer paquete (que podría ser ya un ataque).

        DIFERIDA: se intenta en cada packet_in hasta que el archivo
        exista, porque el controlador arranca antes de que la red lo
        escriba. Una vez cargado, no vuelve a intentarlo."""
        if self._identities_loaded:
            return
        path = config.HOST_IDENTITY_FILE
        if not os.path.exists(path):
            return
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    ip, mac = line.split(",")
                    self.ip_to_mac[ip] = mac.lower()
            self._identities_loaded = True
            self.logger.info("[defense] Identidades de host cargadas (%d hosts).",
                             len(self.ip_to_mac))
        except Exception:
            pass

    def _check_ip_mac(self, claimed_ip, claimed_mac):
        claimed_mac = claimed_mac.lower()
        known = self.ip_to_mac.get(claimed_ip)
        if known is None:
            self.ip_to_mac[claimed_ip] = claimed_mac
            return 1
        return 1 if known == claimed_mac else 0

    def _check_arp_solicited(self, arp_pkt):
        now = time.time()
        if len(self.recent_arp_requests) > 1000:
            self.recent_arp_requests = {
                ip: t for ip, t in self.recent_arp_requests.items()
                if now - t <= ARP_REQUEST_TTL
            }
        if arp_pkt.opcode == 1:
            self.recent_arp_requests[arp_pkt.dst_ip] = now
            return None
        if arp_pkt.opcode == 2:
            t = self.recent_arp_requests.get(arp_pkt.src_ip)
            return 0 if (t is not None and now - t <= ARP_REQUEST_TTL) else 1
        return None

    def _flow_key(self, dpid, get):
        return (dpid, get("eth_src", ""), get("eth_dst", ""),
                get("ipv4_src", ""), get("ipv4_dst", ""), get("ip_proto", ""),
                get("tcp_src", ""), get("tcp_dst", ""),
                get("udp_src", ""), get("udp_dst", ""),
                get("arp_spa", ""), get("arp_tpa", ""), get("arp_op", ""))

    # ------------------------------------------------------------------ #
    # Conmutación L2 básica (para que la red funcione)
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        self._load_host_identities()
        msg = ev.msg
        dp = msg.datapath
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, dp.ofproto.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        # --- Calcular las 3 features del primer paquete (como sdn_monitor) ---
        # y guardarlas indexadas por flow_key, para leerlas al llegar las
        # estadísticas de ese flujo.
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        fields = {"eth_src": eth.src, "eth_dst": eth.dst}
        tcp_flags = ip_mac = arp_unsol = None
        if ip_pkt:
            fields["ipv4_src"] = ip_pkt.src
            fields["ipv4_dst"] = ip_pkt.dst
            fields["ip_proto"] = ip_pkt.proto
            ip_mac = self._check_ip_mac(ip_pkt.src, eth.src)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                fields["tcp_src"] = tcp_pkt.src_port
                fields["tcp_dst"] = tcp_pkt.dst_port
                tcp_flags = tcp_pkt.bits
            elif udp_pkt:
                fields["udp_src"] = udp_pkt.src_port
                fields["udp_dst"] = udp_pkt.dst_port
        elif arp_pkt:
            fields["arp_spa"] = arp_pkt.src_ip
            fields["arp_tpa"] = arp_pkt.dst_ip
            fields["arp_op"] = arp_pkt.opcode
            ip_mac = self._check_ip_mac(arp_pkt.src_ip, arp_pkt.src_mac)
            arp_unsol = self._check_arp_solicited(arp_pkt)

        fk = self._flow_key(dpid, fields.get)
        if tcp_flags is not None:
            self.pending_tcp_flags[fk] = tcp_flags
        if ip_mac is not None:
            self.pending_ip_mac_consistent[fk] = ip_mac
        if arp_unsol is not None:
            self.pending_arp_unsolicited[fk] = arp_unsol

        if out_port != dp.ofproto.OFPP_FLOOD:
            match = parser.OFPMatch(in_port=in_port, eth_dst=eth.dst, eth_src=eth.src)
            self._add_flow(dp, 1, match, actions,
                           idle=FLOW_IDLE_TIMEOUT, hard=FLOW_HARD_TIMEOUT)

        data = msg.data if msg.buffer_id == dp.ofproto.OFP_NO_BUFFER else None
        out = parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                  in_port=in_port, actions=actions, data=data)
        dp.send_msg(out)

    # ------------------------------------------------------------------ #
    # Sondeo periódico de estadísticas
    # ------------------------------------------------------------------ #
    def _monitor_loop(self):
        while True:
            for dp in list(self.datapaths.values()):
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowStatsRequest(dp))
            hub.sleep(POLL_INTERVAL)

    def _cpu_loop(self):
        # cpu_percent con intervalo bloqueante da el uso del proceso Ryu.
        while True:
            self._cpu = self._proc.cpu_percent(interval=1.0)

    # ------------------------------------------------------------------ #
    # Clasificación + mitigación al recibir estadísticas
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        t_event = time.perf_counter()   # inicio de la latencia del plano de control
        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()
        flow_stats = [s for s in ev.msg.body if s.priority not in (0, MITIGATION_PRIORITY)]
        flow_count = len(flow_stats)

        for stat in flow_stats:
            raw, src, dst, dst_port = self._extract(stat, flow_count, dpid)
            if raw is None:
                continue
            flow_key = (dpid, src, dst, dst_port)

            label, infer_ms = self.classifier.predict(raw, now=now)

            mitigated = False
            latency_ms = None
            if label in ATTACK_CLASSES and flow_key not in self.mitigated:
                self._install_drop(dp, stat.match)
                self.mitigated.add(flow_key)
                mitigated = True
                # Latencia del plano de control: evento -> regla enviada
                latency_ms = (time.perf_counter() - t_event) * 1000.0

            self._record_event(now, "classify", dpid, src, dst, dst_port,
                               label, infer_ms, latency_ms, mitigated, raw)

    def _install_drop(self, dp, match):
        """Inyecta una regla OFPFlowMod de prioridad alta con acción DROP
        (lista de acciones vacía = descartar) para el flujo indicado."""
        parser = dp.ofproto_parser
        # Sin instrucciones de acción = DROP en OpenFlow 1.3.
        mod = parser.OFPFlowMod(
            datapath=dp, priority=MITIGATION_PRIORITY, match=match,
            instructions=[], idle_timeout=0, hard_timeout=0,
        )
        dp.send_msg(mod)

    # ------------------------------------------------------------------ #
    # Extracción de características crudas de un flujo (como sdn_monitor)
    # ------------------------------------------------------------------ #
    def _extract(self, stat, flow_count, dpid):
        m = stat.match
        eth_type = m.get("eth_type")
        fk = self._flow_key(dpid, m.get)
        raw = {
            "eth_type": eth_type,
            "flow_count_per_dpid": flow_count,
            "duration_sec": stat.duration_sec,
            "duration_nsec": stat.duration_nsec,
            "packet_count": stat.packet_count,
            "byte_count": stat.byte_count,
            # 3 features del primer paquete (guardadas en _packet_in). Si
            # el flujo ya existía antes de arrancar, quedan como "" (igual
            # criterio que sdn_monitor.py).
            "tcp_flags": self.pending_tcp_flags.get(fk, ""),
            "ip_mac_consistent": self.pending_ip_mac_consistent.get(fk, ""),
            "arp_unsolicited_reply": self.pending_arp_unsolicited.get(fk, ""),
        }
        # tasas diferenciales (pps/bps) respecto al sondeo anterior
        key = (m.get("ipv4_src"), m.get("ipv4_dst"), m.get("eth_src"), m.get("eth_dst"))
        now = time.time()
        prev = self.prev_stats.get(key)
        pps = bps = 0.0
        if prev:
            dt = now - prev[2]
            if dt > 0:
                pps = max(0.0, (stat.packet_count - prev[0]) / dt)
                bps = max(0.0, (stat.byte_count - prev[1]) / dt)
        self.prev_stats[key] = (stat.packet_count, stat.byte_count, now)
        raw["packet_count_per_second"] = round(pps, 2)
        raw["byte_count_per_second"] = round(bps, 2)
        raw["avg_packet_size"] = (stat.byte_count / stat.packet_count) if stat.packet_count else 0

        src = dst = "?"
        dst_port = -1
        if eth_type == ether_types.ETH_TYPE_IP:
            raw["ip_proto"] = m.get("ip_proto")
            raw["ip_src"] = src = m.get("ipv4_src")
            raw["ip_dst"] = dst = m.get("ipv4_dst")
            raw["tcp_src_port"] = m.get("tcp_src")
            raw["tcp_dst_port"] = m.get("tcp_dst")
            raw["udp_src_port"] = m.get("udp_src")
            raw["udp_dst_port"] = m.get("udp_dst")
            dst_port = m.get("tcp_dst") or m.get("udp_dst") or -1
        elif eth_type == ether_types.ETH_TYPE_ARP:
            raw["arp_opcode"] = m.get("arp_op")
            raw["arp_spa"] = src = m.get("arp_spa")
            raw["arp_tpa"] = dst = m.get("arp_tpa")
        else:
            return None, None, None, None
        return raw, src, dst, dst_port

    # ------------------------------------------------------------------ #
    # Registro de eventos a CSV
    # ------------------------------------------------------------------ #
    def _init_events_csv(self):
        with open(EVENTS_CSV, "w", newline="") as f:
            csv.writer(f).writerow(EVENT_HEADERS)

    def _record_event(self, now, event_type, dpid, src, dst, dst_port,
                      label, infer_ms, latency_ms, mitigated, raw):
        row = [
            datetime.now().isoformat(timespec="milliseconds"),
            event_type, f"{dpid:016x}", src, dst, dst_port, label,
            round(infer_ms, 4) if infer_ms is not None else "",
            round(latency_ms, 4) if latency_ms is not None else "",
            int(mitigated),
            raw.get("packet_count_per_second", ""),
            raw.get("distinct_ports", ""),
            raw.get("distinct_sources", ""),
            round(self._cpu, 2),
        ]
        with self._events_lock:
            with open(EVENTS_CSV, "a", newline="") as f:
                csv.writer(f).writerow(row)
