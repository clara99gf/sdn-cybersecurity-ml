#!/usr/bin/env python3
"""
mininet_lab/traffic_generator.py
--------------------------------
Genera el tráfico de la red Mininet intercalando fases de tráfico
normal, scanning, spoofing y ddos en orden aleatorio. Antes de cada fase
escribe su etiqueta en LABEL_FILE, que el controlador (sdn_monitor.py)
lee en cada sondeo para etiquetar las filas del CSV.
 
Cada clase tiene variantes internas (técnicas de escaneo, ARP e IP
spoofing, intensidades y vectores de DDoS, patrones de tráfico normal)
para que el dataset varíe también dentro de cada fase, no solo entre
fases. El tráfico normal incluye a propósito transferencias de alta tasa
(iperf a 5M): sin ellas el modelo podría aprender el atajo "tasa alta =
ataque", que no generaliza a una transferencia legítima grande.
 
Estas mismas funciones las reutiliza la fase 3 (defense/traffic.py), de
modo que el tráfico que el modelo ve en vivo es idéntico al del dataset.
 
Requiere ping, iperf, nmap, hping3 y scapy (los instala setup.sh). Lo
coordina run_01_dataset.py; no se ejecuta directamente.
"""

import os
import random
import sys
import time

# Red de seguridad: ver la misma nota en topology.py.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from mininet.log import info

LABEL_FILE = config.LABEL_FILE
SPOOF_SCRIPT = config.SPOOF_SCRIPT
PYTHON_BIN = config.PYTHON_BIN
LOG_FILE = config.TRAFFIC_LOG_FILE
SETTLE = config.PHASE_SETTLE_SECONDS
MAX_ROWS_PER_PHASE = config.MAX_ROWS_PER_PHASE

# Corte de fase por número de filas. En la generación del dataset (True)
# cada fase se corta al superar MAX_ROWS_PER_PHASE. La fase 3 lo pone a
# False: no hay CSV creciendo y contar sus filas en cada comprobación
# sería un desperdicio.
ENFORCE_ROW_CAP = True

# Cada función de fase devuelve sus actores (las IPs que pasa a
# set_label): generate_dataset lo ignora, la fase 3 lo usa para saber
# quién atacó a quién.
_phase_counter = 0


def set_label(label, actors=None):
    """Escribe la etiqueta de la fase actual, su identificador y, opcional,
    los actores del ataque. Formato: "label,phase_id,ip1|ip2|...".
 
    El id distingue fases del mismo tipo consecutivas (el tipo se sortea,
    así que salen varias seguidas). Sin él, la validación cruzada las
    fusionaría en un solo grupo y perdería fiabilidad al quedarse con
    pocos grupos y muy desiguales.
 
    `actors` son las IPs del ataque (atacantes y víctimas). El controlador
    etiqueta como ataque solo los flujos que las involucran, y como normal
    el tráfico de fondo simultáneo. Es el criterio estándar en datasets
    del área (CICIDS y similares etiquetan por pareja origen/destino del
    ataque, no por franja temporal).
    """
    global _phase_counter
    _phase_counter += 1
    actors_str = "|".join(sorted(set(actors))) if actors else ""
    with open(LABEL_FILE, "w") as f:
        f.write(f"{label},{_phase_counter},{actors_str}")


def _log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")


def _settle():
    """Pausa de asentamiento al final de una fase (ver PHASE_SETTLE_SECONDS)."""
    time.sleep(SETTLE)


def _count_csv_rows():
    """Nº de filas de datos en el CSV (sin contar la cabecera)."""
    if not ENFORCE_ROW_CAP:
        return 0
    try:
        with open(config.CSV_FILE) as f:
            return max(sum(1 for _ in f) - 1, 0)
    except FileNotFoundError:
        return 0


def _cap_exceeded(baseline_rows):
    """True si la fase actual ya ha generado MAX_ROWS_PER_PHASE filas propias."""
    if not ENFORCE_ROW_CAP or not MAX_ROWS_PER_PHASE:
        return False
    return (_count_csv_rows() - baseline_rows) >= MAX_ROWS_PER_PHASE


def _request_flush():
    """Pide al controlador que vacíe las tablas de flujo ahora, sin esperar
    a un cambio de etiqueta. Al cortar una fase por exceso de filas, dejar
    de lanzar tráfico no basta: los flujos ya instalados seguirían vivos
    hasta su hard_timeout, sumando filas de más mientras tanto."""
    try:
        with open(config.FLUSH_REQUEST_FILE, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def _sleep_with_cap(duration, baseline_rows, phase_name, step=0.3):
    """Espera 'duration' segundos en tramos cortos, comprobando en cada uno
    si la fase ha superado su tope de filas. Si lo supera, pide el vaciado
    de flujos y devuelve True para cortar la fase antes de tiempo."""
    elapsed = 0.0
    while elapsed < duration:
        chunk = min(step, duration - elapsed)
        time.sleep(chunk)
        elapsed += chunk
        if _cap_exceeded(baseline_rows):
            _log(f"[cap] {phase_name}: cortada tras superar "
                 f"MAX_ROWS_PER_PHASE ({MAX_ROWS_PER_PHASE} filas). Pidiendo vaciado.")
            _request_flush()
            return True
    return False


# ------------------------------------------------------------------ #
# Lanzar/matar procesos en segundo plano por PID exacto
# ------------------------------------------------------------------ #
def _start_bg(host, cmd):
    """Lanza un comando en segundo plano en la shell del host y devuelve su
    PID, para poder matarlo luego de forma precisa. La salida se añade
    (>>) al log global, no lo sobrescribe."""
    host.cmd(f"{cmd} >> {LOG_FILE} 2>&1 &")
    pid = host.cmd("echo $!").strip()
    return pid


def _kill_pid(host, pid):
    """Mata por PID exacto (SIGKILL)."""
    if pid and pid.isdigit():
        host.cmd(f"kill -9 {pid} 2>/dev/null")


def _kill_all_attack_tools():
    """Mata cualquier herramienta de tráfico que siguiera viva pese al kill
    por PID. Se llama al empezar cada fase, como red de seguridad."""
    for proc in ("hping3", "nmap", "arp_spoof.py", "iperf", "ping"):
        os.system(f"pkill -9 -f {proc} 2>/dev/null")


def _arp_warmup(net, attacker, targets):
    """Resuelve por ARP las direcciones de los objetivos antes de etiquetar
    la fase, para que ese tráfico ARP legítimo no cuente como ataque."""
    for t in targets:
        attacker.cmd(f"ping -c 1 -W 1 {t.IP()} > /dev/null 2>&1")


def check_required_tools(net):
    """"Comprueba que las herramientas de sistema y scapy están disponibles
    desde los hosts de Mininet, y avisa de las que falten."""
    tools = ["ping", "nmap", "hping3", "iperf"]
    h = net.hosts[0]
    missing = [t for t in tools if not h.cmd(f"which {t}").strip()]

    scapy_check = h.cmd(
        f"{PYTHON_BIN} -c "
        "'import sys; print(\"EXE:\", sys.executable); "
        "print(\"PATH:\", sys.path); "
        "import scapy; print(\"SCAPY_OK:\", scapy.__file__)' 2>&1; echo RC=$?"
    )
    if "RC=0" not in scapy_check:
        missing.append(f"scapy (python: {PYTHON_BIN})")
        _log(f"[scapy-check] PYTHON_BIN={PYTHON_BIN}")
        _log(f"[scapy-check] salida completa (ejecutable y sys.path incluidos):\n{scapy_check.strip()}")

    if missing:
        msg = (f"[AVISO] No se encontraron: {', '.join(missing)}. "
               f"Instálalas (ver setup.sh) o esas fases no generarán tráfico real.")
        info(f"*** {msg}\n")
        _log(msg)
    return missing


# ------------------------------------------------------------------ #
# Fase: tráfico normal
# ------------------------------------------------------------------ #
def normal_traffic(net, duration):
    """Tráfico benigno: alterna ping, iperf TCP e iperf UDP entre hosts aleatorios."""
    _kill_all_attack_tools()
    set_label("normal")
    baseline = _count_csv_rows()
    hosts = net.hosts
    started_tcp_servers = set()
    started_udp_servers = set()
    end_time = time.time() + duration
    while time.time() < end_time and not _cap_exceeded(baseline):
        h1, h2 = random.sample(hosts, 2)
        variant = random.choice(["ping", "iperf_tcp", "iperf_udp"])

        if variant == "ping":
            count = random.randint(2, 6)
            h1.cmd(f"ping -c {count} {h2.IP()} >> {LOG_FILE} 2>&1")

        elif variant == "iperf_tcp":
            if h2.name not in started_tcp_servers:
                h2.cmd(f"iperf -s -p 5002 >> {LOG_FILE} 2>&1 &")
                started_tcp_servers.add(h2.name)
                time.sleep(0.3)
            t = random.randint(2, 4)
            h1.cmd(f"iperf -c {h2.IP()} -p 5002 -t {t} >> {LOG_FILE} 2>&1")

        else:  # iperf_udp
            # El ancho de banda alto (5M) está a propósito: así el modelo
            # no aprende el atajo "tasa alta = ataque" (ver docstring).
            bw = random.choice(["200K", "500K", "1M", "5M"])
            if h2.name not in started_udp_servers:
                h2.cmd(f"iperf -s -u -p 5001 >> {LOG_FILE} 2>&1 &")
                started_udp_servers.add(h2.name)
                time.sleep(0.3)
            t = random.randint(2, 4)
            h1.cmd(f"iperf -c {h2.IP()} -u -p 5001 -b {bw} -t {t} >> {LOG_FILE} 2>&1")

        if _sleep_with_cap(random.uniform(1, 3), baseline, "normal"):
            break
    if _cap_exceeded(baseline):
        _request_flush()
    os.system("pkill -9 -f iperf 2>/dev/null")
    os.system("pkill -9 -f ping 2>/dev/null")
    _settle()
    return []


# ------------------------------------------------------------------ #
# Fase: scanning
# ------------------------------------------------------------------ #
def scanning_traffic(net, duration):
    """Escaneo de puertos y red hacia hosts objetivo, combinando nmap (con
    técnicas y velocidades al azar) y sondas ACK sueltas vía hping3. nmap
    lleva -Pn para no hacer descubrimiento previo por ICMP."""
    hosts = net.hosts
    attacker = random.choice(hosts)
    targets = [h for h in hosts if h != attacker]
    _kill_all_attack_tools()
    _arp_warmup(net, attacker, targets)

    # Solo el atacante como actor, no los objetivos: un escaneo apunta a
    # casi todos los hosts, así que incluir los objetivos etiquetaría como
    # scanning todo el tráfico de fondo hacia cualquier host. Un flujo es
    # scanning si lo origina el atacante; como el controlador comprueba
    # origen y destino, con el atacante basta para capturar sus sondas y
    # las respuestas que recibe.
    actors = [attacker.IP()]
    set_label("scanning", actors=actors)
    baseline = _count_csv_rows()
    end_time = time.time() + duration

    scan_types = [
        "-sS", "-sT", "-sU --top-ports 8", "-p 1-20", "-p 1-30",
    ]
    timing = ["-T2", "-T3", "-T4"]  # sin -T5: demasiado agresivo con rangos de puertos

    # La sonda ACK pesa como una variante más entre las de nmap.
    ACK_PROBE_PROBABILITY = 1 / 6

    while time.time() < end_time and not _cap_exceeded(baseline):
        target = random.choice(targets)
        if random.random() < ACK_PROBE_PROBABILITY:
            # Sonda ACK: paquetes TCP con solo el flag ACK, una firma
            # distinta del SYN (ddos/spoofing) y del handshake completo
            # (normal). Puerto origen fijo (-k -s) para no crear un flujo
            # por paquete. Se envían 5 paquetes durante ~1s (-c 5 -i
            # u200000) para que el flujo sobreviva al menos a un sondeo
            # (POLL_INTERVAL=1s) y llegue al CSV.
            port = random.randint(1, 30)
            _log(f"[scanning] {attacker.name} -> {target.IP()} :: hping3 -A -p {port}")
            pid = _start_bg(
                attacker, f"hping3 -A -c 5 -i u200000 -k -s 5099 -p {port} {target.IP()}",
            )
        else:
            flags = f"-Pn {random.choice(scan_types)} {random.choice(timing)}"
            _log(f"[scanning] {attacker.name} -> {target.IP()} :: nmap {flags}")
            pid = _start_bg(attacker, f"nmap {flags} {target.IP()}")
        cut = _sleep_with_cap(random.uniform(1, 2), baseline, "scanning")
        _kill_pid(attacker, pid)
        if cut:
            break

    if _cap_exceeded(baseline):
        _request_flush()
    attacker.cmd("pkill -9 -f nmap 2>/dev/null")
    attacker.cmd("pkill -9 -f hping3 2>/dev/null")
    _settle()
    return actors


# ------------------------------------------------------------------ #
# Fase: spoofing (dos mecanismos: ARP spoofing e IP spoofing)
# ------------------------------------------------------------------ #
def spoofing_traffic(net, duration):
    """Elige al azar entre ARP spoofing (envenenamiento de caché ARP) e IP
    spoofing (TCP con IP origen falsificada vía hping3). Los actores se
    eligen antes de set_label para poder pasárselos al controlador."""
    _kill_all_attack_tools()
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    variant = random.choice(["arp", "ip"])
    if variant == "arp":
        # ARP spoofing multi-víctima: 2-4 víctimas y 1 identidad
        # suplantada, como en un ataque real.
        n_victims = random.randint(2, 4)
        picked = random.sample(others, n_victims + 1)
        victims = picked[:n_victims]
        impersonated = picked[n_victims]
        actors = [attacker.IP(), impersonated.IP()] + [v.IP() for v in victims]
        set_label("spoofing", actors=actors)
        baseline = _count_csv_rows()
        _arp_spoofing(net, duration, baseline, attacker, victims, impersonated)
    else:
        victim, fake_source = random.sample(others, 2)
        actors = [attacker.IP(), victim.IP(), fake_source.IP()]
        set_label("spoofing", actors=actors)
        baseline = _count_csv_rows()
        _ip_spoofing(net, duration, baseline, attacker, victim, fake_source)
    _settle()
    return actors


def _arp_spoofing(net, duration, baseline, attacker, victims, impersonated):
    """Lanza arp_spoof.py: envenena la caché ARP de las víctimas para que
    'impersonated' apunte a la MAC del atacante."""
    victim_ips = " ".join(v.IP() for v in victims)
    _log(f"[spoofing:arp] {attacker.name} suplanta {impersonated.IP()} ante "
         f"{[v.name for v in victims]}")
    pid = _start_bg(
        attacker,
        f"{PYTHON_BIN} {SPOOF_SCRIPT} {impersonated.IP()} {attacker.MAC()} {victim_ips}",
    )
    _sleep_with_cap(duration, baseline, "spoofing:arp")
    _kill_pid(attacker, pid)
    attacker.cmd("pkill -9 -f arp_spoof.py 2>/dev/null")


def _ip_spoofing(net, duration, baseline, attacker, victim, fake_source):
    """El atacante envía TCP a 'victim' falsificando la IP origen como si
    fuera 'fake_source'. Puerto origen fijo (-k -s) para no crear un flujo
    por paquete, y puerto destino variable para cubrir varios servicios."""
    target_port = random.choice([80, 443, 22])

    _log(f"[spoofing:ip] {attacker.name} -> {victim.IP()}:{target_port} con IP falsa {fake_source.IP()}")
    pid = _start_bg(
        attacker,
        f"hping3 --syn -k -s 5000 -a {fake_source.IP()} -p {target_port} -i u20000 {victim.IP()}",
    )
    _sleep_with_cap(duration, baseline, "spoofing:ip")
    _kill_pid(attacker, pid)
    attacker.cmd("pkill -9 -f hping3 2>/dev/null")


# ------------------------------------------------------------------ #
# Fase: ddos
# ------------------------------------------------------------------ #
def ddos_traffic(net, duration, allow_flood=True):
    """DDoS con varios atacantes contra una víctima, alternando vector
    (SYN, UDP, ICMP) e intensidad. allow_flood=False excluye la intensidad
    "--flood", que la fase 3 no usa porque satura el entorno de emulación
    (ver config.DEFENSE_DDOS_ALLOW_FLOOD); la fase 1 la deja en True."""
    hosts = net.hosts
    victim = random.choice(hosts)
    attackers = [h for h in hosts if h != victim]
    n_attackers = random.randint(2, min(4, len(attackers)))
    chosen_attackers = random.sample(attackers, n_attackers)
    _kill_all_attack_tools()
    _arp_warmup(net, victim, chosen_attackers)  # y en el sentido inverso también

    actors = [victim.IP()] + [a.IP() for a in chosen_attackers]
    set_label("ddos", actors=actors)
    baseline = _count_csv_rows()

    flood_type = random.choice(["--syn", "--udp", "--icmp"])
    # Dos tasas limitadas (~500 y ~1000 pps) más el flood, para cubrir un
    # rango de intensidad y no solo los dos extremos.
    intensities = ["rate_limited", "rate_limited_fast"]
    if allow_flood:
        intensities.insert(0, "flood")
    intensity = random.choice(intensities)
    rate_flag = {
        "flood": "--flood",
        "rate_limited": "-i u2000",       # ~500 pps
        "rate_limited_fast": "-i u1000",  # ~1000 pps
    }[intensity]
    # Puerto objetivo variable: un DDoS real no siempre apunta a HTTP.
    target_port = random.choice([80, 443, 22, 53])

    _log(f"[ddos] {[a.name for a in chosen_attackers]} -> {victim.IP()}:{target_port} "
         f":: {flood_type} ({intensity})")
    pids = []
    for i, a in enumerate(chosen_attackers):
        port = 5100 + i  # puerto fijo distinto por atacante, pero estable en el tiempo
        pid = _start_bg(
            a, f"hping3 {flood_type} -k -s {port} {rate_flag} -p {target_port} {victim.IP()}",
        )
        pids.append((a, pid))

    _sleep_with_cap(duration, baseline, "ddos")

    for a, pid in pids:
        _kill_pid(a, pid)
        a.cmd("pkill -9 -f hping3 2>/dev/null")
    _settle()
    return actors


# ------------------------------------------------------------------ #
# Orquestador principal
# ------------------------------------------------------------------ #
def generate_dataset(net, total_duration=None, min_phase=None, max_phase=None, target_rows=None):
    """Ejecuta fases de tráfico de tipo aleatorio hasta alcanzar target_rows
    filas o agotar total_duration segundos."""
    total_duration = total_duration or config.TOTAL_DURATION
    min_phase = min_phase or config.MIN_PHASE_DURATION
    max_phase = max_phase or config.MAX_PHASE_DURATION
    target_rows = config.TARGET_ROWS if target_rows is None else target_rows

    # Empezar cada tirada con el log limpio: _log() añade (modo "a") para
    # no perder nada dentro de una tirada, así que sin este borrado se
    # acumularían varias tiradas en el mismo fichero.
    open(LOG_FILE, "w").close()

    check_required_tools(net)
    _kill_all_attack_tools()  # por si algo sobrevivió a una ejecución anterior
    info(f"*** Esperando {config.STARTUP_SETTLE_SECONDS}s a que expiren los flujos "
         f"residuales del pingAll() inicial antes de la primera fase...\n")
    time.sleep(config.STARTUP_SETTLE_SECONDS)

    phases = [normal_traffic, scanning_traffic, spoofing_traffic, ddos_traffic]
    elapsed = 0
    n_phases = 0
    while elapsed < total_duration:
        rows = _count_csv_rows()
        if target_rows and rows >= target_rows:
            info(f"*** Objetivo de {target_rows} filas alcanzado ({rows} filas, "
                 f"{n_phases} fases). Deteniendo generación (transcurridos {elapsed}s).\n")
            break

        phase = random.choice(phases)
        phase_duration = random.randint(min_phase, max_phase)
        info(f"*** Fase {n_phases + 1}: {phase.__name__} durante {phase_duration}s "
             f"(filas: {rows}{f'/{target_rows}' if target_rows else ''}, "
             f"transcurrido: {elapsed}s / {total_duration}s)\n")
        phase(net, phase_duration)
        elapsed += phase_duration + SETTLE
        n_phases += 1
    set_label("normal")
    _kill_all_attack_tools()  # nada debe seguir enviando tráfico al terminar
    info(f"*** Generación de tráfico finalizada. "
         f"Filas totales: {_count_csv_rows()}. Fases ejecutadas: {n_phases}.\n")
