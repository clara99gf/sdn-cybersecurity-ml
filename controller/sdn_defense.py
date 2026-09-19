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
  4. Registra métricas a un CSV de eventos (results/metrics/defense_events.csv):
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
import sys
import threading
import time
from datetime import datetime

# ryu-manager ejecuta este archivo directamente (no como parte del
# paquete 'controller'), así que 'from controller.x import ...' falla y
# ryu muere al arrancar. Añadimos al sys.path tanto la raíz del proyecto
# (para 'import config') como la carpeta controller/ (para
# 'import live_classifier'), igual que hace sdn_monitor.py con config.
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config
from live_classifier import LiveClassifier

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

# Sondeo cada 1s (igual que en la generación del dataset). Se probó
# bajarlo a 0.5s para capturar mejor las sondas de escaneo, pero con el
# modelo tardando ~30ms por flujo y cientos de flujos por sondeo, 0.5s
# saturaba el controlador. 1s es el equilibrio estable.
POLL_INTERVAL = config.POLL_INTERVAL
FLOW_IDLE_TIMEOUT = 2  # corto en la defensa (ver FLOW_HARD_TIMEOUT abajo)
# Hard timeout CORTO para las reglas de reenvío en la defensa (3s, en vez
# del valor del dataset). El escaneo abre cientos de conexiones a puertos
# distintos, cada una instalando una regla granular; con un hard timeout
# largo el switch acumula cientos de reglas y el controlador se satura,
# dejando la red inestable para la prueba siguiente. Con 3s las reglas se
# autoeliminan enseguida y el switch nunca se llena. No afecta a la
# captura: 3s cubre de sobra un sondeo (POLL_INTERVAL=1s).
FLOW_HARD_TIMEOUT = 3
ATTACK_CLASSES = {"ddos", "scanning", "spoofing"}
MITIGATION_PRIORITY = 100  # muy por encima de las reglas normales
# Marca (cookie) de las reglas DROP de mitigación, para poder borrarlas
# selectivamente sin tocar la table-miss ni las reglas de reenvío.
DROP_COOKIE = 0xD0D0
# Duración de una regla DROP de mitigación (segundos). No son permanentes
# a propósito: así la red NUNCA puede quedar bloqueada indefinidamente
# por reglas residuales (causaba 100% de pings caídos entre pruebas), y
# además es más realista -un IDS re-evalúa en vez de bloquear para
# siempre por una sola detección-. 20s corta el ataque de forma efectiva
# dentro de una prueba y se limpia solo.
DROP_TIMEOUT = 20
# Máximo de flujos que el controlador CLASIFICA por sondeo (salvaguarda
# de rendimiento). Ojo: NO altera flow_count_per_dpid, que se calcula
# antes del recorte y debe reflejar los flujos reales del switch -es
# una característica del modelo y falsearla sería engañarlo-. Con la
# clasificación por lotes esto ya no es el cuello de botella; el tope
# solo acota el peor caso.
MAX_FLOWS_PER_POLL = 100
# Eventos que se acumulan en memoria antes de volcarlos al CSV de una vez.
# Escribir evento a evento bloqueaba el proceso (ver _record_event).
EVENT_FLUSH_EVERY = 50
ARP_REQUEST_TTL = 5.0      # ventana para "respuesta ARP solicitada" (ver sdn_monitor)

METRICS_DIR = os.path.join(config.PROJECT_ROOT, "results", "metrics")
os.makedirs(METRICS_DIR, exist_ok=True)
EVENTS_CSV = os.path.join(METRICS_DIR, "defense_events.csv")
# Archivo-interruptor: el orquestador lo crea al empezar una prueba y lo
# borra al terminar. El controlador SOLO clasifica y mitiga mientras
# existe. Así, durante el arranque (pingAll) y los periodos de reposo,
# el controlador actúa como un switch normal y NO bloquea nada -antes,
# clasificaba el tráfico del pingAll inicial como ataque y lo mitigaba,
# tumbando la red antes de empezar-.
ACTIVE_FLAG = os.path.join(config.RUNTIME_DIR, "defense_active.flag")
# El controlador crea este archivo cuando ha TERMINADO de limpiar las
# reglas (DROP + reenvío) y reinstalar la table-miss al final de una
# prueba. El orquestador lo espera antes de hacer el pingAll de
# recuperación, para no pingear con reglas DROP aún activas (que
# bloquearían la red y colgarían el pingAll durante minutos).
CLEAN_FLAG = os.path.join(config.RUNTIME_DIR, "defense_clean.flag")

EVENT_HEADERS = [
    "timestamp", "traffic_phase", "event_type", "dpid", "src", "dst", "dst_port",
    "predicted_label", "inference_ms", "control_latency_ms",
    "mitigated", "pkt_rate", "flow_count_per_dpid",
    "distinct_ports", "distinct_targets",
    "distinct_sources", "ryu_cpu_percent",
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
        self._was_active = False   # estado de "prueba activa" (ver _handle_transition)
        self._events_lock = threading.Lock()
        self._init_events_csv()

        self.monitor_thread = hub.spawn(self._monitor_loop)
        # Muestreo de CPU del proceso Ryu: con psutil si está disponible,
        # y si no, leyendo /proc (siempre disponible en Linux). Así la
        # gráfica de CPU nunca sale plana a 0 por falta de psutil.
        if self._proc is not None:
            hub.spawn(self._cpu_loop)
        else:
            hub.spawn(self._cpu_loop_proc)

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
        # match_fields se usa para DOS cosas: la clave del flujo y el
        # match de la regla OpenFlow. Debe incluir eth_type y los campos
        # L3/L4 -si la regla solo tuviera eth_src/eth_dst, las
        # estadísticas de ese flujo NO traerían IP/puertos/ARP y el
        # modelo no podría clasificar (era el bug del CSV vacío)-.
        match_fields = {"in_port": in_port, "eth_src": eth.src, "eth_dst": eth.dst}
        fields = {"eth_src": eth.src, "eth_dst": eth.dst}
        tcp_flags = ip_mac = arp_unsol = None
        if ip_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_IP
            match_fields["ipv4_src"] = ip_pkt.src
            match_fields["ipv4_dst"] = ip_pkt.dst
            match_fields["ip_proto"] = ip_pkt.proto
            fields["ipv4_src"] = ip_pkt.src
            fields["ipv4_dst"] = ip_pkt.dst
            fields["ip_proto"] = ip_pkt.proto
            ip_mac = self._check_ip_mac(ip_pkt.src, eth.src)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port
                fields["tcp_src"] = tcp_pkt.src_port
                fields["tcp_dst"] = tcp_pkt.dst_port
                tcp_flags = tcp_pkt.bits
            elif udp_pkt:
                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port
                fields["udp_src"] = udp_pkt.src_port
                fields["udp_dst"] = udp_pkt.dst_port
        elif arp_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_ARP
            match_fields["arp_spa"] = arp_pkt.src_ip
            match_fields["arp_tpa"] = arp_pkt.dst_ip
            match_fields["arp_op"] = arp_pkt.opcode
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
            # Regla GRANULAR (con eth_type/IP/puertos/ARP): así las
            # estadísticas de este flujo traerán esos campos y el modelo
            # podrá clasificarlo.
            match = parser.OFPMatch(**match_fields)
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
        """Loop LIGERO: solo pide estadísticas periódicamente. La gestión
        de transiciones (limpieza al cambiar de prueba) y el volcado de
        eventos se hacen DENTRO del handler de estadísticas
        (_handle_transition, llamado desde _stats_reply), igual que en el
        monitor del dataset -que cambia de fase decenas de veces sin
        romperse-. Motivo: con un escaneo que genera 1000+ eventos, el
        handler de estadísticas acapara el hilo eventlet y este loop no
        conseguía turno para detectar la transición y limpiar. Al hacer
        ambas cosas en el mismo handler, no compiten."""
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    parser = dp.ofproto_parser
                    dp.send_msg(parser.OFPFlowStatsRequest(dp))
            except Exception as e:
                self.logger.warning("[defense] error pidiendo estadísticas: %s", e)
            hub.sleep(POLL_INTERVAL)

    def _handle_transition(self):
        """Detecta el cambio activo/inactivo y, al terminar una prueba,
        vuelca los eventos, limpia las reglas y confirma. Se llama al
        principio de _stats_reply (en el mismo hilo que procesa las
        estadísticas), para que no compita con la clasificación."""

        # Volcado periódico de seguridad
        self._flush_events()

        active = os.path.exists(ACTIVE_FLAG)

        phase = "inactive"
        if active:
            try:
                with open(ACTIVE_FLAG) as f:
                    phase = f.read().strip() or "?"
            except OSError:
                phase = "?"

        self.logger.warning(
            "[DEBUG] TRANSITION active=%s was_active=%s phase=%s",
            active,
            self._was_active,
            phase,
        )

        if active == self._was_active:
            return

        was_active_prev = self._was_active
        self._was_active = active

        if was_active_prev and not active:
            self._flush_events()

        try:
            self._clear_mitigation_rules()
        except Exception as e:
            self.logger.warning("[defense] error limpiando reglas: %s", e)

        if was_active_prev and not active:
            try:
                open(CLEAN_FLAG, "w").close()
            except OSError as e:
                self.logger.warning(
                    "[defense] no se pudo escribir CLEAN_FLAG: %s", e
                )

    def _clear_mitigation_rules(self):
        """Deja los switches limpios y funcionales: borra TODAS las reglas
        y reinstala la table-miss (mismo enfoque que el _flush_all_flows
        del monitor del dataset, que cambia de fase decenas de veces sin
        romperse).

        Cada switch se trata en su propio try: si uno falla (se ha
        desconectado, rechaza el mensaje...), los demás se limpian igual y
        el estado interno se resetea de todas formas. Un fallo aquí no
        puede dejar el controlador a medias."""
        self.logger.warning("[DEBUG] LIMPIANDO REGLAS DE MITIGACION")
        for dp in list(self.datapaths.values()):
            try:
                parser = dp.ofproto_parser
                ofp = dp.ofproto
                # Borrar todas las reglas (match comodín).
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch(),
                ))
                # Reinstalar la table-miss (el borrado comodín se la lleva).
                miss = [parser.OFPActionOutput(ofp.OFPP_CONTROLLER,
                                               ofp.OFPCML_NO_BUFFER)]
                self._add_flow(dp, 0, parser.OFPMatch(), miss)
            except Exception as e:
                self.logger.warning("[defense] no se pudo limpiar dpid=%s: %s",
                                    getattr(dp, "id", "?"), e)
        # El estado interno se resetea SIEMPRE, pase lo que pase arriba.
        self.mac_to_port.clear()
        self.prev_stats.clear()
        self.pending_tcp_flags.clear()
        self.pending_ip_mac_consistent.clear()
        self.pending_arp_unsolicited.clear()
        self.mitigated.clear()
        self.logger.info("[defense] Switches limpios y table-miss reinstalada.")
        self.logger.warning("[DEBUG] LIMPIEZA TERMINADA")

    def _cpu_loop(self):
        # cpu_percent SIN interval (no bloqueante). Con interval=1.0,
        # psutil hace un time.sleep(1) REAL que bloquea TODO el proceso
        # eventlet 1s por vuelta -ahogando el hilo de sondeo, que dejaba
        # de pedir estadísticas y de limpiar-. Sin interval, devuelve el
        # uso acumulado desde la llamada anterior (la 1ª da 0.0) y cedemos
        # el control con hub.sleep (cooperativo).
        self._proc.cpu_percent(None)
        while True:
            self._cpu = self._proc.cpu_percent(None)
            hub.sleep(1)

    def _cpu_loop_proc(self):
        """Medición de CPU SIN psutil, leyendo /proc/self/stat de Linux.
        Usa hub.sleep (cooperativo con eventlet), NO time.sleep -este
        último bloquearía todo el proceso y ahogaría el sondeo-."""
        hz = os.sysconf("SC_CLK_TCK")
        ncpu = os.cpu_count() or 1

        def _read():
            with open("/proc/self/stat") as f:
                parts = f.read().split()
            return int(parts[13]) + int(parts[14])

        prev = _read()
        prev_t = time.time()
        while True:
            hub.sleep(1)   # cooperativo (antes time.sleep -> bloqueaba)
            cur = _read()
            cur_t = time.time()
            dt = cur_t - prev_t
            used = (cur - prev) / hz          # segundos de CPU consumidos
            self._cpu = max(0.0, 100.0 * used / (dt * ncpu))
            prev, prev_t = cur, cur_t

    # ------------------------------------------------------------------ #
    # Clasificación + mitigación al recibir estadísticas
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        # Gestionar la transición de estado (fin de prueba -> limpiar) EN
        # ESTE handler, no en un hilo aparte: con un escaneo que genera
        # miles de eventos, este handler acapara el hilo eventlet y un
        # loop separado no conseguía turno para limpiar. Se hace primero,
        # SIEMPRE (aunque la prueba ya no esté activa: es justo la
        # transición activo->inactivo la que hay que detectar aquí).
        self._handle_transition()

        # Solo clasificar y mitigar cuando hay una prueba en marcha (el
        # orquestador crea ACTIVE_FLAG). Fuera de una prueba -arranque,
        # pingAll, reposo- el controlador actúa como un switch normal y
        # no toca el tráfico.
        if not os.path.exists(ACTIVE_FLAG):
            self.logger.info(
                "[DEBUG] stats recibidas, ACTIVE_FLAG=%s",
                os.path.exists(ACTIVE_FLAG)
            )
            return
        # Tipo de prueba en marcha (lo escribe el orquestador en el flag).
        try:
            with open(ACTIVE_FLAG) as f:
                phase = f.read().strip() or "?"
        except OSError:
            phase = "?"
        t_event = time.perf_counter()   # inicio de la latencia del plano de control
        dp = ev.msg.datapath
        dpid = dp.id
        now = time.time()
        flow_stats = [s for s in ev.msg.body if s.priority not in (0, MITIGATION_PRIORITY)]
        flow_count = len(flow_stats)

        # Límite de flujos clasificados por sondeo (salvaguarda: el escaneo
        # puede generar cientos). Con la clasificación por lotes ya no es
        # el cuello de botella, pero acota el peor caso.
        if flow_count > MAX_FLOWS_PER_POLL:
            flow_stats = sorted(flow_stats, key=lambda s: s.packet_count,
                                reverse=True)[:MAX_FLOWS_PER_POLL]

        self.logger.warning(
            "[DEBUG] STATS_START phase=%s dpid=%s flows=%d",
            phase,
            dpid,
            len(flow_stats),
        )


        # --- Paso 1: extraer las características crudas de cada flujo ---
        items = []   # (stat, raw, src, dst, dst_port)
        for stat in flow_stats:
            try:
                raw, src, dst, dst_port = self._extract(stat, flow_count, dpid)
                if raw is None:
                    continue
                items.append((stat, raw, src, dst, dst_port))
            except Exception as e:
                self.logger.warning("[defense] error extrayendo un flujo: %s", e)

        self.logger.warning(
            "[DEBUG] STATS_EXTRACTED phase=%s dpid=%s items=%d",
            phase,
            dpid,
            len(items),
        )

        if not items:
            self.logger.warning(
                "[DEBUG] STATS_END_NO_ITEMS phase=%s dpid=%s",
                phase,
                dpid,
            )
            return

        # --- Paso 2: clasificar TODOS de una vez (una sola llamada al
        # modelo). Clasificar flujo a flujo costaba ~30ms cada uno y
        # saturaba el controlador (22s de trabajo por cada segundo de
        # sondeo); en lote son unos pocos ms en total. ---
        self.logger.warning(
            "[DEBUG] PREDICT_START phase=%s dpid=%s items=%d",
            phase,
            dpid,
            len(items),
        )

        try:
            results = self.classifier.predict_batch([it[1] for it in items], now=now)
        except Exception as e:
            self.logger.warning("[defense] error clasificando el lote: %s", e)
            return

        self.logger.warning(
            "[DEBUG] PREDICT_END phase=%s dpid=%s results=%d",
            phase,
            dpid,
            len(results),
        )

        # --- Paso 3: mitigar y registrar ---
        for idx, (
            (stat, raw, src, dst, dst_port),
            (label, infer_ms, wfeats)
        ) in enumerate(zip(items, results)):
            try:
                self.logger.warning(
                    "[DEBUG] FLOW_START phase=%s dpid=%s src=%s label=%s",
                    phase,
                    dpid,
                    src,
                    label,
                )

                raw["distinct_ports"] = wfeats["distinct_ports"]
                raw["distinct_targets"] = wfeats["distinct_targets"]
                raw["distinct_sources"] = wfeats["distinct_sources"]

                mitigated = False
                latency_ms = None
                # Mitigar POR IP ATACANTE, no por flujo. Un escaneo genera
                # CIENTOS de flujos (uno por puerto); instalar un DROP por
                # cada uno son cientos de mensajes OpenFlow por sondeo, que
                # SATURAN el canal de control y ahogan el controlador -era
                # la causa de que se bloqueara durante scanning-. Con un
                # solo DROP a la IP origen del ataque se corta todo el
                # tráfico de ese atacante, con UN mensaje en vez de
                # cientos. Es además como actúa un IDS real (bloquea al
                # host malicioso, no cada conexión suya).
                if label in ATTACK_CLASSES and src and src != "?" and src not in self.mitigated:
                    self.logger.warning(
                        "[DEBUG] MITIGATION_START "
                        "phase=%s dpid=%s src=%s label=%s",
                        phase,
                        dpid,
                        src,
                        label,
                    )
                    self._install_drop_by_src(dp, src)
                    self.mitigated.add(src)
                    mitigated = True
                    latency_ms = (time.perf_counter() - t_event) * 1000.0

                self.logger.warning(
                    "[DEBUG] RECORD_START "
                    "phase=%s dpid=%s src=%s label=%s",
                    phase,
                    dpid,
                    src,
                    label,
                )

                self._record_event(now, phase, "classify", dpid, src, dst, dst_port,
                                   label, infer_ms, latency_ms, mitigated, raw)
                
                self.logger.warning(
                    "[DEBUG] RECORD_END "
                    "phase=%s dpid=%s src=%s label=%s",
                    phase,
                    dpid,
                    src,
                    label,
                )

            except Exception as e:
                # Un flujo problemático no debe abortar el procesamiento de
                # los demás ni matar el handler de estadísticas.
                self.logger.warning("[defense] error clasificando un flujo: %s", e)
                continue
            
        self.logger.warning(
            "[DEBUG] STATS_END phase=%s dpid=%s items=%d",
            phase,
            dpid,
            len(items),
        )

    def _install_drop_by_src(self, dp, src_ip):
        """Instala UNA regla DROP que bloquea todo el tráfico de una IP
        origen (el atacante), en vez de una regla por flujo. Un escaneo o
        un DDoS lo genera una sola IP (o unas pocas), así que con un DROP
        por IP se corta el ataque entero con un único mensaje OpenFlow,
        sin saturar el canal de control. Cubre tanto IPv4 (ipv4_src) como
        ARP (arp_spa)."""

        self.logger.warning(
            "[DEBUG] INSTALANDO DROP src=%s dpid=%s",
            src_ip, dp.id
        )

        parser = dp.ofproto_parser
        for match in (
            parser.OFPMatch(eth_type=ether_types.ETH_TYPE_IP, ipv4_src=src_ip),
            parser.OFPMatch(eth_type=ether_types.ETH_TYPE_ARP, arp_spa=src_ip),
        ):
            mod = parser.OFPFlowMod(
                datapath=dp, priority=MITIGATION_PRIORITY, match=match,
                instructions=[], idle_timeout=0, hard_timeout=DROP_TIMEOUT,
                cookie=DROP_COOKIE,
            )
            dp.send_msg(mod)

    def _install_drop(self, dp, match):
        """Inyecta una regla OFPFlowMod de prioridad alta con acción DROP
        (lista de acciones vacía = descartar) para el flujo indicado.

        Con hard_timeout = DROP_TIMEOUT (no permanente): la mitigación
        corta el ataque durante ese tiempo y luego la regla se
        autoelimina. Es importante por dos motivos:
          1. Robustez: unas reglas DROP permanentes que no se limpien
             bien dejan la RED BLOQUEADA (daba 100% de pings caídos y
             cuelgues de minutos entre pruebas).
          2. Realismo: un IDS real no bloquea para siempre por una única
             detección; re-evalúa. Si el ataque sigue, el flujo se vuelve
             a detectar y a bloquear -que es justo lo que se ve en las
             gráficas: DROP repetidos mientras el atacante insiste-.
        """
        parser = dp.ofproto_parser
        # Sin instrucciones de acción = DROP en OpenFlow 1.3.
        mod = parser.OFPFlowMod(
            datapath=dp, priority=MITIGATION_PRIORITY, match=match,
            instructions=[], idle_timeout=0, hard_timeout=DROP_TIMEOUT,
            cookie=DROP_COOKIE,
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
        # Escribe la cabecera SOLO si el archivo no existe. Así el
        # orquestador puede "resetear" las métricas simplemente borrando
        # el CSV, y el controlador repone la cabecera en el siguiente
        # evento -sin borrar lo que se vaya acumulando entre pruebas-.
        if not os.path.exists(EVENTS_CSV):
            with open(EVENTS_CSV, "w", newline="") as f:
                csv.writer(f).writerow(EVENT_HEADERS)

    def _record_event(self, now, phase, event_type, dpid, src, dst, dst_port,
                      label, infer_ms, latency_ms, mitigated, raw):
        """Encola un evento en memoria. NO escribe a disco en cada evento.

        Antes se hacía open/write/close del CSV por CADA evento: con
        cientos de eventos (un escaneo genera 500+), eso son cientos de
        operaciones de disco BLOQUEANTES. En el modelo de concurrencia de
        Ryu (eventlet, un solo hilo cooperativo) cada escritura bloquea
        TODO el proceso, incluido el hilo de sondeo -que dejaba de pedir
        estadísticas y de confirmar la limpieza, rompiendo las pruebas
        siguientes-. Ahora se acumulan en memoria y se vuelcan por lotes
        (ver _flush_events)."""
        row = [
            datetime.now().isoformat(timespec="milliseconds"),
            phase, event_type, f"{dpid:016x}", src, dst, dst_port, label,
            round(infer_ms, 4) if infer_ms is not None else "",
            round(latency_ms, 4) if latency_ms is not None else "",
            int(mitigated),
            raw.get("packet_count_per_second", ""),
            raw.get("flow_count_per_dpid", ""),
            raw.get("distinct_ports", ""),
            raw.get("distinct_targets", ""),
            raw.get("distinct_sources", ""),
            round(self._cpu, 2),
        ]
        with self._events_lock:
            self._events.append(row)
            pendientes = len(self._events)
        # Volcado por lotes: una sola escritura cada EVENT_FLUSH_EVERY
        # eventos, en vez de una por evento.
        if pendientes >= EVENT_FLUSH_EVERY:
            self._flush_events()

    def _flush_events(self):
        """Vuelca a disco los eventos acumulados (una sola escritura)."""
        with self._events_lock:
            if not self._events:
                return
            pendientes, self._events = self._events, []
        try:
            self._init_events_csv()  # repone la cabecera si el CSV fue borrado
            self.logger.warning(
                "[DEBUG] FLUSH EVENTS: %d eventos -> %s",
                len(pendientes),
                EVENTS_CSV
             )
            with open(EVENTS_CSV, "a", newline="") as f:
                csv.writer(f).writerows(pendientes)
                self.logger.warning(
                    "[DEBUG] CSV EXISTS=%s",
                    os.path.exists(EVENTS_CSV)
                )
        except OSError as e:
            self.logger.warning("[defense] no se pudieron volcar eventos: %s", e)
