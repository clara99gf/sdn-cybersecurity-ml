"""
sdn_defense.py
--------------
Controlador Ryu para la FASE DE DETECCIÓN Y MITIGACIÓN en vivo.

A diferencia de controller/sdn_monitor.py (que solo OBSERVA y escribe un
CSV etiquetado para entrenar), este controlador:

  1. Conmuta y sondea las estadísticas de flujo EXACTAMENTE igual que el
     monitor (mismas reglas granulares, mismos timeouts, mismo cálculo de
     contadores y tasas) -cualquier diferencia aquí cambiaría las
     features respecto al entrenamiento (training-serving skew)-.
  2. Clasifica cada flujo EN VIVO con el modelo entrenado
     (controller/live_classifier.py), con el mismo preprocesado.
  3. MITIGA: cuando una conversación (par MAC origen -> MAC destino) se
     clasifica como ataque de forma repetida, instala en TODOS los
     switches una regla OpenFlow de prioridad alta y acción DROP para
     ese par (ver _mitigate para el porqué de hacerlo así).
  4. Registra métricas en results/events/defense_events.csv: por cada
     flujo evaluado guarda la predicción, la etiqueta REAL (calculada con
     el mismo criterio que el dataset), el tiempo de inferencia, la
     latencia del plano de control y si se aplicó DROP.

El CPU del proceso Ryu se muestrea en un hilo aparte y se vuelca también
al CSV de eventos (gráfica/tabla CPU vs latencia).

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
# paquete 'controller'), así que se añaden al sys.path la raíz del
# proyecto (para 'import config') y la carpeta controller/ (para
# 'import live_classifier' y 'import sdn_monitor').
_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
for _p in (_ROOT, _HERE):
    if _p not in sys.path:
        sys.path.insert(0, _p)

import config
from live_classifier import LiveClassifier
# Criterio de etiquetado por flujo: se REUTILIZA el del monitor que generó
# el dataset (no una copia), para que la "etiqueta real" de la fase 3
# signifique exactamente lo mismo que la etiqueta con la que se entrenó.
# (Importar la clase no la arranca: ryu-manager solo lanza las apps
# definidas en el propio módulo que se le pasa, sdn_defense.)
from sdn_monitor import SDNFlowMonitor

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

_label_for_flow = SDNFlowMonitor._label_for_flow

# --------------------------------------------------------------------- #
# Parámetros (los de conmutación/sondeo, IGUALES que en el dataset)
# --------------------------------------------------------------------- #
POLL_INTERVAL = config.POLL_INTERVAL
# Los timeouts de las reglas de reenvío deben ser IGUALES que en la
# generación del dataset: determinan cuánto vive un flujo en el switch y,
# por tanto, flow_count_per_dpid -la feature más importante del modelo-.
FLOW_IDLE_TIMEOUT = config.FLOW_IDLE_TIMEOUT
FLOW_HARD_TIMEOUT = config.FLOW_HARD_TIMEOUT
ARP_REQUEST_TTL = 5.0      # igual que sdn_monitor.py

# --------------------------------------------------------------------- #
# Parámetros de la mitigación
# --------------------------------------------------------------------- #
ATTACK_CLASSES = {"ddos", "scanning", "spoofing"}
MITIGATION_PRIORITY = 100  # muy por encima de las reglas de reenvío (1)
DROP_COOKIE = 0xD0D0       # marca de las reglas DROP
# Parámetros ajustables de la mitigación: definidos en config.py (sección
# "Fase 3"), donde está explicado cada uno.
DROP_TIMEOUT = config.DEFENSE_DROP_TIMEOUT
MITIGATION_CONFIRMATIONS = config.DEFENSE_MITIGATION_CONFIRMATIONS
CONFIRM_WINDOW_S = config.DEFENSE_CONFIRM_WINDOW_S
ACTIVATION_GRACE_S = config.DEFENSE_ACTIVATION_GRACE_S

# Eventos acumulados en memoria antes de volcarlos al CSV de una vez
# (escribir evento a evento bloqueaba el hilo eventlet).
EVENT_FLUSH_EVERY = 50

EVENTS_DIR = os.path.join(config.PROJECT_ROOT, "results", "events")
os.makedirs(EVENTS_DIR, exist_ok=True)
EVENTS_CSV = os.path.join(EVENTS_DIR, "defense_events.csv")

# Ficheros de coordinación con run_03_defense.py:
#  - ACTIVE_FLAG: existe solo mientras hay una prueba en marcha. Contiene
#    "tipo|ejecución" (p.ej. "scanning|3": la prueba de scanning de la
#    3ª batería). Fuera de una prueba el controlador conmuta como
#    un switch normal y no clasifica ni bloquea nada.
#  - READY_FLAG: el controlador lo crea cuando, tras activar una prueba,
#    ya ha vaciado las tablas y pasado el margen ACTIVATION_GRACE_S. El
#    orquestador espera a este flag antes de lanzar el tráfico.
#  - CLEAN_FLAG: el controlador lo crea al terminar de limpiar las reglas
#    al final de una prueba.
ACTIVE_FLAG = os.path.join(config.RUNTIME_DIR, "defense_active.flag")
READY_FLAG = os.path.join(config.RUNTIME_DIR, "defense_ready.flag")
CLEAN_FLAG = os.path.join(config.RUNTIME_DIR, "defense_clean.flag")

EVENT_HEADERS = [
    "timestamp", "traffic_phase", "run", "event_type", "dpid",
    "src", "dst", "eth_src", "eth_dst", "ip_proto", "dst_port",
    "predicted_label", "true_label",
    "inference_ms", "control_latency_ms", "mitigated",
    "pkt_rate", "flow_count_per_dpid",
    "distinct_ports", "distinct_targets", "distinct_sources",
    "ryu_cpu_percent",
]


def _read_label_file():
    """Lee LABEL_FILE (lo escribe set_label() de traffic_generator, igual
    que en la generación del dataset). Formato "label,phase_id,ip1|ip2".
    Devuelve (label, actores)."""
    try:
        with open(config.LABEL_FILE) as f:
            raw = f.read().strip()
    except OSError:
        return "normal", frozenset()
    parts = raw.split(",") if raw else []
    label = (parts[0].strip() if parts else "") or "normal"
    actors = frozenset(
        ip for ip in (parts[2].split("|") if len(parts) > 2 else []) if ip
    )
    return label, actors


class SDNDefense(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SDNDefense, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.datapaths = {}
        # Mismo estado que sdn_monitor.py, con el mismo significado:
        self.prev_stats = {}                 # flow_key -> (pkts, bytes, t)
        self.pending_offsets = {}            # flow_key -> (pkts, bytes) del 1er paquete
        self.pending_tcp_flags = {}
        self.pending_ip_mac_consistent = {}
        self.pending_arp_unsolicited = {}
        self.ip_to_mac = {}                  # identidad de host (no se limpia)
        self.recent_arp_requests = {}
        self._identities_loaded = False

        # Estado de la mitigación
        self.mitigated = {}                  # (eth_src, eth_dst) -> instante de expiración del DROP
        self._attack_rounds = {}             # (eth_src, eth_dst) -> {nº de sondeo: instante}

        self.classifier = LiveClassifier()
        self.logger.info("[defense] Modelo de clasificación cargado.")

        self._proc = psutil.Process(os.getpid()) if _HAS_PSUTIL else None
        self._cpu = 0.0
        self._events = []
        self._events_lock = threading.Lock()
        self._was_active = False
        self._ignore_until = 0.0
        self._ready_written = False
        self._warned_missing_ports = False
        self._init_events_csv()

        self.monitor_thread = hub.spawn(self._monitor_loop)
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
        self._install_table_miss(ev.msg.datapath)
        self.logger.info("[defense] Switch conectado: %016x", ev.msg.datapath.id)

    def _install_table_miss(self, dp):
        parser = dp.ofproto_parser
        actions = [parser.OFPActionOutput(dp.ofproto.OFPP_CONTROLLER,
                                          dp.ofproto.OFPCML_NO_BUFFER)]
        self._add_flow(dp, 0, parser.OFPMatch(), actions)

    def _add_flow(self, dp, priority, match, actions, idle=0, hard=0):
        parser = dp.ofproto_parser
        inst = [parser.OFPInstructionActions(dp.ofproto.OFPIT_APPLY_ACTIONS, actions)]
        dp.send_msg(parser.OFPFlowMod(datapath=dp, priority=priority, match=match,
                                      instructions=inst, idle_timeout=idle,
                                      hard_timeout=hard))

    # ------------------------------------------------------------------ #
    # Features del packet_in (idéntico a sdn_monitor.py)
    # ------------------------------------------------------------------ #
    def _load_host_identities(self):
        """Siembra ip_to_mac con las identidades reales de los hosts
        (mismo mecanismo que sdn_monitor.py). Diferida: se intenta en cada
        packet_in hasta que run_03_defense.py haya escrito el archivo."""
        if self._identities_loaded or not os.path.exists(config.HOST_IDENTITY_FILE):
            return
        try:
            with open(config.HOST_IDENTITY_FILE) as f:
                for line in f:
                    line = line.strip()
                    if line:
                        ip, mac = line.split(",")
                        self.ip_to_mac[ip] = mac.lower()
            self._identities_loaded = True
            self.logger.info("[defense] Identidades de host cargadas (%d hosts).",
                             len(self.ip_to_mac))
        except Exception as e:
            self.logger.warning("[defense] No se pudieron cargar identidades: %s", e)

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
        # MISMA clave que SDNFlowMonitor._flow_key.
        return (dpid, get("eth_src", ""), get("eth_dst", ""),
                get("ipv4_src", ""), get("ipv4_dst", ""), get("ip_proto", ""),
                get("tcp_src", ""), get("tcp_dst", ""),
                get("udp_src", ""), get("udp_dst", ""),
                get("arp_spa", ""), get("arp_tpa", ""), get("arp_op", ""))

    # ------------------------------------------------------------------ #
    # Conmutación L2 con reglas granulares (copia del monitor)
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in(self, ev):
        self._load_host_identities()
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto
        parser = dp.ofproto_parser
        in_port = msg.match["in_port"]
        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocols(ethernet.ethernet)[0]
        if eth.ethertype == ether_types.ETH_TYPE_LLDP:
            return

        dpid = dp.id
        self.mac_to_port.setdefault(dpid, {})
        self.mac_to_port[dpid][eth.src] = in_port
        out_port = self.mac_to_port[dpid].get(eth.dst, ofp.OFPP_FLOOD)
        actions = [parser.OFPActionOutput(out_port)]

        match_fields = {"in_port": in_port, "eth_src": eth.src, "eth_dst": eth.dst}
        tcp_flags = ip_mac = arp_unsol = None
        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        arp_pkt = pkt.get_protocol(arp.arp)
        if ip_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_IP
            match_fields["ipv4_src"] = ip_pkt.src
            match_fields["ipv4_dst"] = ip_pkt.dst
            match_fields["ip_proto"] = ip_pkt.proto
            ip_mac = self._check_ip_mac(ip_pkt.src, eth.src)
            tcp_pkt = pkt.get_protocol(tcp.tcp)
            udp_pkt = pkt.get_protocol(udp.udp)
            if tcp_pkt:
                match_fields["tcp_src"] = tcp_pkt.src_port
                match_fields["tcp_dst"] = tcp_pkt.dst_port
                tcp_flags = tcp_pkt.bits
            elif udp_pkt:
                match_fields["udp_src"] = udp_pkt.src_port
                match_fields["udp_dst"] = udp_pkt.dst_port
        elif arp_pkt:
            match_fields["eth_type"] = ether_types.ETH_TYPE_ARP
            match_fields["arp_spa"] = arp_pkt.src_ip
            match_fields["arp_tpa"] = arp_pkt.dst_ip
            # arp_sha también en el match, como en el monitor: cambia la
            # granularidad de los flujos ARP (y con ello flow_count).
            match_fields["arp_sha"] = arp_pkt.src_mac
            match_fields["arp_op"] = arp_pkt.opcode
            ip_mac = self._check_ip_mac(arp_pkt.src_ip, arp_pkt.src_mac)
            arp_unsol = self._check_arp_solicited(arp_pkt)

        if out_port != ofp.OFPP_FLOOD:
            self._add_flow(dp, 1, parser.OFPMatch(**match_fields), actions,
                           idle=FLOW_IDLE_TIMEOUT, hard=FLOW_HARD_TIMEOUT)
            # Igual que el monitor: los pending_* solo se registran cuando
            # se instala regla (si no, ese flujo nunca aparecerá en las
            # estadísticas), y se compensa el paquete que generó el
            # packet_in (el switch no lo cuenta en el FlowStats).
            fk = self._flow_key(dpid, match_fields.get)
            extra_p, extra_b = self.pending_offsets.get(fk, (0, 0))
            self.pending_offsets[fk] = (extra_p + 1, extra_b + msg.total_len)
            if tcp_flags is not None:
                self.pending_tcp_flags[fk] = tcp_flags
            if ip_mac is not None:
                self.pending_ip_mac_consistent[fk] = ip_mac
            if arp_unsol is not None:
                self.pending_arp_unsolicited[fk] = arp_unsol

        data = msg.data if msg.buffer_id == ofp.OFP_NO_BUFFER else None
        dp.send_msg(parser.OFPPacketOut(datapath=dp, buffer_id=msg.buffer_id,
                                        in_port=in_port, actions=actions, data=data))

    # ------------------------------------------------------------------ #
    # Sondeo periódico y gestión de transiciones de prueba
    # ------------------------------------------------------------------ #
    def _monitor_loop(self):
        """Solo pide estadísticas. Las transiciones y el volcado de eventos
        se gestionan dentro del handler de estadísticas, para que no
        compitan por el hilo eventlet con la clasificación."""
        while True:
            try:
                for dp in list(self.datapaths.values()):
                    dp.send_msg(dp.ofproto_parser.OFPFlowStatsRequest(dp))
            except Exception as e:
                self.logger.warning("[defense] error pidiendo estadísticas: %s", e)
            hub.sleep(POLL_INTERVAL)

    def _handle_transition(self):
        self._flush_events()
        active = os.path.exists(ACTIVE_FLAG)
        if active == self._was_active:
            return
        was_active = self._was_active
        self._was_active = active

        if not was_active and active:
            # INICIO de prueba: tablas limpias + margen de gracia antes de
            # clasificar (ver ACTIVATION_GRACE_S).
            self._clear_all_rules()
            self._ignore_until = time.time() + ACTIVATION_GRACE_S
            self._ready_written = False
            self.logger.info("[defense] Prueba activada: tablas vaciadas, "
                             "margen de %.1fs antes de clasificar.", ACTIVATION_GRACE_S)
        else:
            # FIN de prueba: volcar, limpiar y confirmar al orquestador.
            self._flush_events()
            self._clear_all_rules()
            try:
                open(CLEAN_FLAG, "w").close()
            except OSError as e:
                self.logger.warning("[defense] no se pudo escribir CLEAN_FLAG: %s", e)

    def _clear_all_rules(self):
        """Borra todas las reglas (reenvío y DROP), reinstala la table-miss
        y resetea el estado transitorio -mismo enfoque que el
        _flush_all_flows del monitor en cada cambio de fase-."""
        for dp in list(self.datapaths.values()):
            try:
                parser = dp.ofproto_parser
                ofp = dp.ofproto
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, command=ofp.OFPFC_DELETE,
                    out_port=ofp.OFPP_ANY, out_group=ofp.OFPG_ANY,
                    match=parser.OFPMatch(), priority=0, instructions=[],
                ))
                self._install_table_miss(dp)
            except Exception as e:
                self.logger.warning("[defense] no se pudo limpiar dpid=%s: %s",
                                    getattr(dp, "id", "?"), e)
        self.mac_to_port.clear()
        self.prev_stats.clear()
        self.pending_offsets.clear()
        self.pending_tcp_flags.clear()
        self.pending_ip_mac_consistent.clear()
        self.pending_arp_unsolicited.clear()
        self.mitigated.clear()
        self._attack_rounds.clear()
        # ip_to_mac NO se limpia (identidad de host, igual que el monitor).
        self.logger.info("[defense] Switches limpios y table-miss reinstalada.")

    def _cpu_loop(self):
        # cpu_percent SIN interval (no bloqueante) + hub.sleep cooperativo.
        self._proc.cpu_percent(None)
        while True:
            self._cpu = self._proc.cpu_percent(None)
            hub.sleep(1)

    def _cpu_loop_proc(self):
        """CPU sin psutil, leyendo /proc/self/stat (hub.sleep, no time.sleep)."""
        hz = os.sysconf("SC_CLK_TCK")
        ncpu = os.cpu_count() or 1

        def _read():
            with open("/proc/self/stat") as f:
                parts = f.read().split()
            return int(parts[13]) + int(parts[14])

        prev, prev_t = _read(), time.time()
        while True:
            hub.sleep(1)
            cur, cur_t = _read(), time.time()
            dt = cur_t - prev_t
            self._cpu = max(0.0, 100.0 * ((cur - prev) / hz) / (dt * ncpu))
            prev, prev_t = cur, cur_t

    # ------------------------------------------------------------------ #
    # Clasificación + mitigación al recibir estadísticas
    # ------------------------------------------------------------------ #
    @set_ev_cls(ofp_event.EventOFPFlowStatsReply, MAIN_DISPATCHER)
    def _stats_reply(self, ev):
        self._handle_transition()
        if not self._was_active:
            return
        now = time.time()
        if now < self._ignore_until:
            return   # respuestas con flujos de antes de la prueba
        if not self._ready_written:
            try:
                open(READY_FLAG, "w").close()
            except OSError:
                pass
            self._ready_written = True

        try:
            with open(ACTIVE_FLAG) as f:
                content = f.read().strip()
        except OSError:
            content = ""
        phase, _, run = content.partition("|")
        phase = phase or "?"
        run = run or "1"
        phase_label, actors = _read_label_file()

        t_event = time.perf_counter()   # inicio de la latencia del plano de control
        dp = ev.msg.datapath
        dpid = dp.id
        # Igual que el monitor: fuera la table-miss (prioridad 0), y aquí
        # también las reglas DROP propias (no existen en el dataset).
        flow_stats = [s for s in ev.msg.body
                      if s.priority not in (0, MITIGATION_PRIORITY)]
        flow_count = len(flow_stats)
        self._log_poll(dpid, flow_stats)

        items = []
        for stat in flow_stats:
            try:
                raw = self._extract(stat, flow_count, dpid, now)
                if raw is not None:
                    items.append((stat, raw))
            except Exception as e:
                self.logger.warning("[defense] error extrayendo un flujo: %s", e)
        if not items:
            return

        # Clasificación por lotes (una sola llamada al modelo). El
        # WindowTracker se alimenta con TODOS los flujos, igual que el
        # preprocesado hace con todas las filas del dataset.
        try:
            results = self.classifier.predict_batch([it[1] for it in items], now=now)
        except Exception as e:
            self.logger.warning("[defense] error clasificando el lote: %s", e)
            return

        for (stat, raw), (label, infer_ms, wfeats) in zip(items, results):
            try:
                true_label = _label_for_flow(
                    phase_label, actors, raw.get("ip_src"), raw.get("ip_dst"),
                    raw.get("arp_spa"), raw.get("arp_tpa"),
                )
                if true_label == "warmup":
                    true_label = "normal"
                mitigated, latency_ms = False, None
                if label in ATTACK_CLASSES:
                    mitigated = self._mitigate(raw.get("eth_src"), raw.get("eth_dst"), now)
                    if mitigated:
                        latency_ms = (time.perf_counter() - t_event) * 1000.0
                self._record_event(now, phase, run, dpid, raw, label, true_label,
                                   infer_ms, latency_ms, mitigated, wfeats)
            except Exception as e:
                self.logger.warning("[defense] error procesando un flujo: %s", e)

    def _mitigate(self, eth_src, eth_dst, now):
        """Decide si bloquear la conversación eth_src -> eth_dst y, si
        procede, instala el DROP en TODOS los switches. Devuelve True si
        se ha instalado ahora.

        Por qué por PAR DE MACs y no por IP origen (como antes):
          - El dataset etiqueta como ataque todo flujo que involucre a un
            actor, víctimas incluidas (sus respuestas al escáner o al DDoS
            también son "scanning"/"ddos"). El modelo dice "este flujo
            pertenece a un ataque", no "este origen es el atacante".
            Bloquear la IP origen acababa bloqueando a las VÍCTIMAS (en la
            batería anterior: las 3 víctimas del escaneo y la del DDoS).
            Bloqueando el par, una respuesta de la víctima solo corta esa
            respuesta hacia el atacante, que es inofensivo.
          - En spoofing la IP origen es FALSA: bloquearla dejaba fuera al
            host inocente suplantado. La MAC origen, en cambio, es la del
            remitente real (en estos ataques no se falsifica).
          - Un falso positivo corta una conversación, no un host entero.
          - En todos los switches: bloquear solo en el que reportó el
            flujo no corta el tráfico que no pasa por él.
        Confirmación: hace falta que el par se clasifique como ataque en
        MITIGATION_CONFIRMATIONS sondeos distintos dentro de
        CONFIRM_WINDOW_S (ver la constante)."""
        if not eth_src or not eth_dst:
            return False
        pair = (eth_src, eth_dst)
        if now < self.mitigated.get(pair, 0):
            return False          # ya bloqueado y la regla sigue vigente
        rnd = int(now / POLL_INTERVAL)
        rounds = self._attack_rounds.setdefault(pair, {})
        rounds[rnd] = now
        for r in [r for r, t in rounds.items() if now - t > CONFIRM_WINDOW_S]:
            del rounds[r]
        if len(rounds) < MITIGATION_CONFIRMATIONS:
            return False
        for dp in list(self.datapaths.values()):
            try:
                parser = dp.ofproto_parser
                dp.send_msg(parser.OFPFlowMod(
                    datapath=dp, priority=MITIGATION_PRIORITY,
                    match=parser.OFPMatch(eth_src=eth_src, eth_dst=eth_dst),
                    instructions=[],       # sin acciones = DROP en OpenFlow 1.3
                    idle_timeout=0, hard_timeout=DROP_TIMEOUT, cookie=DROP_COOKIE,
                ))
            except Exception as e:
                self.logger.warning("[defense] no se pudo instalar DROP en dpid=%s: %s",
                                    getattr(dp, "id", "?"), e)
        self.mitigated[pair] = now + DROP_TIMEOUT
        rounds.clear()
        self.logger.info("[defense] DROP %s -> %s (%ds)", eth_src, eth_dst, DROP_TIMEOUT)
        return True

    def _log_poll(self, dpid, flow_stats):
        """Diagnóstico en logs/ryu_defense.log (mismo estilo que el monitor),
        incluyendo cuántos flujos TCP/UDP traen puertos en el match. Si hay
        flujos TCP/UDP SIN puertos, avisa una vez: es la pista para el
        problema de dst_port=-1 visto en la batería anterior."""
        n_arp = n_ip = n_tcp = n_udp = n_l4_sin_puerto = 0
        for s in flow_stats:
            m = s.match
            et = m.get("eth_type")
            if et == ether_types.ETH_TYPE_ARP:
                n_arp += 1
            elif et == ether_types.ETH_TYPE_IP:
                n_ip += 1
                proto = m.get("ip_proto")
                if proto == 6:
                    n_tcp += 1
                    if m.get("tcp_dst") is None:
                        n_l4_sin_puerto += 1
                elif proto == 17:
                    n_udp += 1
                    if m.get("udp_dst") is None:
                        n_l4_sin_puerto += 1
        self.logger.info("[poll] dpid=%016x flows=%d (arp=%d ip=%d tcp=%d udp=%d "
                         "l4_sin_puerto=%d)", dpid, len(flow_stats), n_arp, n_ip,
                         n_tcp, n_udp, n_l4_sin_puerto)
        if n_l4_sin_puerto and not self._warned_missing_ports:
            self._warned_missing_ports = True
            ejemplo = next((s.match for s in flow_stats
                            if s.match.get("ip_proto") in (6, 17)), None)
            self.logger.warning("[defense] AVISO: flujos TCP/UDP sin puertos en el "
                                "match. Ejemplo de match: %s", ejemplo)

    # ------------------------------------------------------------------ #
    # Extracción de características crudas (MISMO cálculo que el monitor)
    # ------------------------------------------------------------------ #
    def _extract(self, stat, flow_count, dpid, now):
        m = stat.match
        eth_type = m.get("eth_type")
        if eth_type not in (ether_types.ETH_TYPE_IP, ether_types.ETH_TYPE_ARP):
            return None
        fk = self._flow_key(dpid, m.get)

        # Contadores con la compensación del primer paquete (como el monitor).
        extra_p, extra_b = self.pending_offsets.pop(fk, (0, 0))
        packet_count = stat.packet_count + extra_p
        byte_count = stat.byte_count + extra_b

        # Tasas: MISMO cálculo que sdn_monitor.py. Antes aquí se indexaba
        # por (ip_src, ip_dst, eth_src, eth_dst), con lo que flujos
        # distintos del mismo par (ICMP y TCP, p.ej.) se pisaban entre sí
        # y salían tasas imposibles (100.000-7.000.000 pkt/s); y un flujo
        # visto por primera vez tenía tasa 0 en vez de la estimación por
        # edad que usa el dataset.
        prev = self.prev_stats.get(fk)
        if prev and packet_count >= prev[0]:
            dt = max(now - prev[2], 1e-6)
            pps = max((packet_count - prev[0]) / dt, 0)
            bps = max((byte_count - prev[1]) / dt, 0)
        else:
            age = stat.duration_sec + stat.duration_nsec / 1e9
            pps = packet_count / age if age > 0 else 0.0
            bps = byte_count / age if age > 0 else 0.0
        self.prev_stats[fk] = (packet_count, byte_count, now)

        raw = {
            "eth_type": eth_type,
            "eth_src": m.get("eth_src"),
            "eth_dst": m.get("eth_dst"),
            "flow_count_per_dpid": flow_count,
            "duration_sec": stat.duration_sec,
            "duration_nsec": stat.duration_nsec,
            "packet_count": packet_count,
            "byte_count": byte_count,
            "packet_count_per_second": round(pps, 2),
            "byte_count_per_second": round(bps, 2),
            "avg_packet_size": round(byte_count / packet_count, 2) if packet_count > 0 else 0,
            "tcp_flags": self.pending_tcp_flags.get(fk, ""),
            "ip_mac_consistent": self.pending_ip_mac_consistent.get(fk, ""),
            "arp_unsolicited_reply": self.pending_arp_unsolicited.get(fk, ""),
        }
        if eth_type == ether_types.ETH_TYPE_IP:
            raw["ip_proto"] = m.get("ip_proto")
            raw["ip_src"] = m.get("ipv4_src")
            raw["ip_dst"] = m.get("ipv4_dst")
            raw["tcp_src_port"] = m.get("tcp_src")
            raw["tcp_dst_port"] = m.get("tcp_dst")
            raw["udp_src_port"] = m.get("udp_src")
            raw["udp_dst_port"] = m.get("udp_dst")
        else:
            raw["arp_opcode"] = m.get("arp_op")
            raw["arp_spa"] = m.get("arp_spa")
            raw["arp_tpa"] = m.get("arp_tpa")
        return raw

    # ------------------------------------------------------------------ #
    # Registro de eventos a CSV (en memoria + volcado por lotes)
    # ------------------------------------------------------------------ #
    def _init_events_csv(self):
        # Cabecera solo si el archivo no existe: el orquestador "resetea"
        # las métricas borrando el CSV y aquí se repone. Si existe pero es
        # de una versión anterior (otras columnas), se empieza de nuevo
        # para no mezclar formatos en el mismo fichero.
        if os.path.exists(EVENTS_CSV):
            try:
                with open(EVENTS_CSV) as f:
                    header = f.readline().strip().split(",")
            except OSError:
                header = EVENT_HEADERS
            if header == EVENT_HEADERS:
                return
        if True:
            with open(EVENTS_CSV, "w", newline="") as f:
                csv.writer(f).writerow(EVENT_HEADERS)

    def _record_event(self, now, phase, run, dpid, raw, label, true_label,
                      infer_ms, latency_ms, mitigated, wfeats):
        src = raw.get("ip_src") or raw.get("arp_spa") or ""
        dst = raw.get("ip_dst") or raw.get("arp_tpa") or ""
        dst_port = raw.get("tcp_dst_port") or raw.get("udp_dst_port") or -1
        row = [
            datetime.now().isoformat(timespec="milliseconds"),
            phase, run, "classify", f"{dpid:016x}",
            src, dst, raw.get("eth_src") or "", raw.get("eth_dst") or "",
            raw.get("ip_proto") if raw.get("ip_proto") is not None else "",
            dst_port, label, true_label,
            round(infer_ms, 4) if infer_ms is not None else "",
            round(latency_ms, 4) if latency_ms is not None else "",
            int(mitigated),
            raw.get("packet_count_per_second", ""),
            raw.get("flow_count_per_dpid", ""),
            wfeats.get("distinct_ports", ""),
            wfeats.get("distinct_targets", ""),
            wfeats.get("distinct_sources", ""),
            round(self._cpu, 2),
        ]
        with self._events_lock:
            self._events.append(row)
            pendientes = len(self._events)
        if pendientes >= EVENT_FLUSH_EVERY:
            self._flush_events()

    def _flush_events(self):
        with self._events_lock:
            if not self._events:
                return
            pendientes, self._events = self._events, []
        try:
            self._init_events_csv()
            with open(EVENTS_CSV, "a", newline="") as f:
                csv.writer(f).writerows(pendientes)
        except OSError as e:
            self.logger.warning("[defense] no se pudieron volcar eventos: %s", e)
