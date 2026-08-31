#!/usr/bin/env python3
"""
traffic_generator.py
---------------------
Orquesta la generación de tráfico dentro de la red Mininet, intercalando
fases de tráfico normal, scanning, spoofing y ddos en orden aleatorio.
Antes de cada fase escribe la etiqueta correspondiente en LABEL_FILE,
que el controlador Ryu (sdn_monitor.py) lee en cada ronda de muestreo
para etiquetar las filas del CSV.

Cada clase de tráfico tiene, además, VARIANTES internas (distintos
tipos de escaneo, dos mecanismos de spoofing, intensidades de DDoS
distintas, patrones de tráfico normal distintos) para que el dataset
no solo varíe de fase en fase, sino también dentro de cada fase. Y
ninguna fase puede generar más de MAX_ROWS_PER_PHASE filas (ver
config.py), para que TARGET_ROWS se reparta entre muchas fases
distintas en vez de que una sola acapare el dataset.

Dependencias de red (instaladas mediante setup.sh a nivel de sistema / venv):
    - Binarios Linux: ping, iperf, nmap, hping3.
    - Librería Python: scapy.

Ejecución:
    Este módulo es coordinado automáticamente por el orquestador principal
    run_all.py (ver EJECUCION.md).
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


def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label)


def _log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")


def _settle():
    """Pausa de asentamiento al final de una fase (ver PHASE_SETTLE_SECONDS)."""
    time.sleep(SETTLE)


def _count_csv_rows():
    """Nº de filas de datos en el CSV (sin contar la cabecera)."""
    try:
        with open(config.CSV_FILE) as f:
            return max(sum(1 for _ in f) - 1, 0)
    except FileNotFoundError:
        return 0


def _cap_exceeded(baseline_rows):
    """True si la fase actual ya ha generado MAX_ROWS_PER_PHASE filas propias."""
    if not MAX_ROWS_PER_PHASE:
        return False
    return (_count_csv_rows() - baseline_rows) >= MAX_ROWS_PER_PHASE


def _request_flush():
    """Pide al controlador que vacíe las tablas de flujo AHORA MISMO, sin
    esperar a un cambio de etiqueta. Necesario porque el generador solo
    puede detectar que una fase se ha pasado de filas DESPUÉS de que el
    controlador ya las haya escrito (el CSV solo crece en cada sondeo);
    y aunque dejemos de lanzar tráfico nuevo en cuanto lo detectamos, los
    flujos YA CREADOS seguirían vivos hasta su hard_timeout, sumando más
    filas de la cuenta mientras tanto si no se vacían de inmediato."""
    try:
        with open(config.FLUSH_REQUEST_FILE, "w") as f:
            f.write(str(time.time()))
    except OSError:
        pass


def _sleep_with_cap(duration, baseline_rows, phase_name, step=0.3):
    """
    Sustituye la espera pasiva (time.sleep) dividiéndola en intervalos breves (step=0.3s).

    En cada ciclo verifica si se ha excedido el máximo de filas de la fase. Si se alcanza
    el tope, solicita el vaciado inmediato de flujos y aborta la fase de forma anticipada.
    """
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
    """
    Ejecuta un comando en segundo plano en la shell del host y recupera su PID exacto.
    Redirige STDOUT y STDERR hacia el archivo de log global.
    """
    host.cmd(f"{cmd} > {LOG_FILE} 2>&1 &")
    pid = host.cmd("echo $!").strip()
    return pid


def _kill_pid(host, pid):
    """Mata por PID exacto (SIGKILL)."""
    if pid and pid.isdigit():
        host.cmd(f"kill -9 {pid} 2>/dev/null")


def _kill_all_attack_tools():
    """Red de seguridad ADICIONAL:
    mata cualquier proceso de las herramientas de tráfico que pudiera
    haber quedado vivo pese al kill por PID. Se llama al empezar CADA fase."""
    for proc in ("hping3", "nmap", "arp_spoof.py", "iperf", "ping"):
        os.system(f"pkill -9 -f {proc} 2>/dev/null")


def _arp_warmup(net, attacker, targets):
    """
    Fuerza la resolución ARP previa entre el host atacante y los objetivos.

    Asegura que el tráfico de descubrimiento ARP (legítimo) se registre antes de
    que se active la etiqueta de ataque en el controlador SDN.
    """
    for t in targets:
        attacker.cmd(f"ping -c 1 -W 1 {t.IP()} > /dev/null 2>&1")


def check_required_tools(net):
    """
    Verifica que las herramientas de sistema y librerías de Python requeridas
    estén estén disponibles desde los hosts virtuales de Mininet.
    """
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
            bw = random.choice(["200K", "500K", "1M"])
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


# ------------------------------------------------------------------ #
# Fase: scanning
# ------------------------------------------------------------------ #
def scanning_traffic(net, duration):
    """
    Simula escaneos de puertos/red con nmap hacia hosts objetivos.
    Aplica el parámetro -Pn para evitar el descubrimiento de hosts mediante
    ICMP y utiliza diferentes tipos y velocidades de escaneo de forma
    aleatoria y secuencial para generar tráfico de scanning controlado.
    """
    hosts = net.hosts
    attacker = random.choice(hosts)
    targets = [h for h in hosts if h != attacker]
    _kill_all_attack_tools()
    _arp_warmup(net, attacker, targets)

    set_label("scanning")
    baseline = _count_csv_rows()
    end_time = time.time() + duration

    scan_types = ["-sS", "-sT", "-sU --top-ports 8", "-p 1-20"]
    timing = ["-T2", "-T3", "-T4"]  # sin -T5: demasiado explosivo con rangos de puertos

    while time.time() < end_time and not _cap_exceeded(baseline):
        target = random.choice(targets)
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
    _settle()


# ------------------------------------------------------------------ #
# Fase: spoofing (dos mecanismos: ARP spoofing e IP spoofing)
# ------------------------------------------------------------------ #
def spoofing_traffic(net, duration):
    """Elige aleatoriamente entre ARP spoofing (envenenamiento de caché ARP)
    e IP spoofing (paquetes TCP con IP origen falsificada vía hping3)."""
    _kill_all_attack_tools()
    set_label("spoofing")
    baseline = _count_csv_rows()
    variant = random.choice(["arp", "ip"])
    if variant == "arp":
        _arp_spoofing(net, duration, baseline)
    else:
        _ip_spoofing(net, duration, baseline)
    _settle()


def _arp_spoofing(net, duration, baseline):
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    victim, impersonated = random.sample(others, 2)

    _log(f"[spoofing:arp] {attacker.name} suplanta {impersonated.IP()} ante {victim.IP()}")
    pid = _start_bg(
        attacker,
        f"{PYTHON_BIN} {SPOOF_SCRIPT} {victim.IP()} {impersonated.IP()} {attacker.MAC()}",
    )
    _sleep_with_cap(duration, baseline, "spoofing:arp")
    _kill_pid(attacker, pid)
    attacker.cmd("pkill -9 -f arp_spoof.py 2>/dev/null")


def _ip_spoofing(net, duration, baseline):
    """El atacante envía TCP a 'victim' falsificando la IP origen como si
    fuera 'fake_source'.
    Puerto origen fijo (-k -s) para no generar un flujo nuevo por paquete."""
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    victim, fake_source = random.sample(others, 2)

    _log(f"[spoofing:ip] {attacker.name} -> {victim.IP()} con IP falsa {fake_source.IP()}")
    pid = _start_bg(
        attacker,
        f"hping3 --syn -k -s 5000 -a {fake_source.IP()} -p 80 -i u20000 {victim.IP()}",
    )
    _sleep_with_cap(duration, baseline, "spoofing:ip")
    _kill_pid(attacker, pid)
    attacker.cmd("pkill -9 -f hping3 2>/dev/null")


# ------------------------------------------------------------------ #
# Fase: ddos
# ------------------------------------------------------------------ #
def ddos_traffic(net, duration):
    """
    Ejecuta ataques de denegación de servicio distribuidos usando múltiples atacantes.
    Alterna vectores de ataque (SYN, UDP, ICMP) e intensidades (flood o tasa limitada).
    """
    hosts = net.hosts
    victim = random.choice(hosts)
    attackers = [h for h in hosts if h != victim]
    n_attackers = random.randint(2, min(4, len(attackers)))
    chosen_attackers = random.sample(attackers, n_attackers)
    _kill_all_attack_tools()
    _arp_warmup(net, victim, chosen_attackers)  # y en el sentido inverso también

    set_label("ddos")
    baseline = _count_csv_rows()

    flood_type = random.choice(["--syn", "--udp", "--icmp"])
    intensity = random.choice(["flood", "rate_limited"])
    rate_flag = "--flood" if intensity == "flood" else "-i u2000"  # ~500 pps si acotado

    _log(f"[ddos] {[a.name for a in chosen_attackers]} -> {victim.IP()} "
         f":: {flood_type} ({intensity})")
    pids = []
    for i, a in enumerate(chosen_attackers):
        port = 5100 + i  # puerto fijo distinto por atacante, pero estable en el tiempo
        pid = _start_bg(
            a, f"hping3 {flood_type} -k -s {port} {rate_flag} -p 80 {victim.IP()}",
        )
        pids.append((a, pid))

    _sleep_with_cap(duration, baseline, "ddos")

    for a, pid in pids:
        _kill_pid(a, pid)
        a.cmd("pkill -9 -f hping3 2>/dev/null")
    _settle()


# ------------------------------------------------------------------ #
# Orquestador principal
# ------------------------------------------------------------------ #
def generate_dataset(net, total_duration=None, min_phase=None, max_phase=None, target_rows=None):
    """
    Coordina la secuencia global de fases de tráfico.

    El proceso finaliza al alcanzar la meta de registros ('target_rows')
    o al cumplirse el tiempo límite ('total_duration').
    """
    total_duration = total_duration or config.TOTAL_DURATION
    min_phase = min_phase or config.MIN_PHASE_DURATION
    max_phase = max_phase or config.MAX_PHASE_DURATION
    target_rows = config.TARGET_ROWS if target_rows is None else target_rows

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
