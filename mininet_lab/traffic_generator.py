#!/usr/bin/env python3
"""
traffic_generator.py
---------------------
Orquesta la generación de tráfico dentro de la red Mininet, intercalando
fases de tráfico normal, scanning, spoofing y ddos en orden aleatorio.
Antes de cada fase escribe la etiqueta correspondiente en LABEL_FILE,
que el controlador Ryu (sdn_monitor.py) lee en cada ronda de muestreo
para etiquetar las filas del CSV.

Requisitos en las imágenes de host de Mininet:
    - iperf
    - nmap
    - hping3
    - scapy (pip3 install scapy)
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from mininet.log import info

LABEL_FILE = config.LABEL_FILE
SPOOF_SCRIPT = config.SPOOF_SCRIPT
PYTHON_BIN = config.PYTHON_BIN
LOG_FILE = config.TRAFFIC_LOG_FILE


def set_label(label):
    with open(LABEL_FILE, "w") as f:
        f.write(label)


def _log(msg):
    with open(LOG_FILE, "a") as f:
        f.write(f"{msg}\n")


def check_required_tools(net):
    """
    Comprueba, en un host cualquiera, que las herramientas necesarias
    estén instaladas. Si falta alguna, avisa (esa fase no generará
    tráfico real aunque el script no falle, así que si luego no ves
    una clase en el CSV, revisa primero este aviso y el LOG_FILE).
    """
    tools = ["nmap", "hping3", "iperf"]
    h = net.hosts[0]
    missing = [t for t in tools if not h.cmd(f"which {t}").strip()]
    if missing:
        msg = (f"[AVISO] No se encontraron en los hosts: {', '.join(missing)}. "
               f"Instálalas (ver setup.sh) o esas fases no generarán tráfico real.")
        info(f"*** {msg}\n")
        _log(msg)
    return missing


# ------------------------------------------------------------------ #
# Fases de tráfico
# ------------------------------------------------------------------ #
def normal_traffic(net, duration):
    """Tráfico benigno: ping + pequeñas transferencias iperf entre hosts aleatorios."""
    set_label("normal")
    hosts = net.hosts
    end_time = time.time() + duration
    while time.time() < end_time:
        h1, h2 = random.sample(hosts, 2)
        h1.cmd(f"ping -c 3 {h2.IP()} >> {LOG_FILE} 2>&1 &")
        h2.cmd(f"iperf -s -u -p 5001 >> {LOG_FILE} 2>&1 &")
        time.sleep(0.5)
        h1.cmd(f"iperf -c {h2.IP()} -u -p 5001 -b 500K -t 3 >> {LOG_FILE} 2>&1 &")
        time.sleep(random.uniform(2, 5))
    os.system("pkill -f iperf 2>/dev/null")


def scanning_traffic(net, duration):
    """Escaneo de red/puertos con nmap desde un host atacante hacia varios objetivos.

    IMPORTANTE: se usa '-Pn' en todos los escaneos para que nmap NO haga
    primero un descubrimiento de host (ping scan) y lo dé por "caído" si
    ese descubrimiento falla; sin '-Pn' es fácil que nmap decida que el
    objetivo está "down" y no llegue a enviar ni un solo paquete de
    escaneo, que es la causa más probable de que no veas 'scanning' en
    el CSV.
    """
    set_label("scanning")
    hosts = net.hosts
    attacker = random.choice(hosts)
    targets = [h for h in hosts if h != attacker]
    end_time = time.time() + duration
    # -Pn siempre presente; variamos el tipo/alcance del escaneo
    scan_flags = [
        "-Pn -sS -T4",
        "-Pn -sT -T4",
        "-Pn -sU -T4 --top-ports 20",
        "-Pn -T4 -p 1-200",
    ]
    while time.time() < end_time:
        target = random.choice(targets)
        flags = random.choice(scan_flags)
        cmd = f"nmap {flags} {target.IP()} >> {LOG_FILE} 2>&1 &"
        _log(f"[scanning] {attacker.name} -> {target.IP()} :: nmap {flags}")
        attacker.cmd(cmd)
        time.sleep(random.uniform(1, 3))
    attacker.cmd("pkill -f nmap 2>/dev/null")


def spoofing_traffic(net, duration):
    """ARP spoofing: un atacante envenena la caché ARP de otros dos hosts."""
    set_label("spoofing")
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    victim, impersonated = random.sample(others, 2)

    cmd = (f"{PYTHON_BIN} {SPOOF_SCRIPT} {victim.IP()} {impersonated.IP()} "
           f"{attacker.MAC()} >> {LOG_FILE} 2>&1 &")
    _log(f"[spoofing] {attacker.name} suplanta {impersonated.IP()} ante {victim.IP()}")
    attacker.cmd(cmd)
    time.sleep(duration)
    attacker.cmd("pkill -f arp_spoof.py 2>/dev/null")


def ddos_traffic(net, duration):
    """DDoS distribuido: varios hosts inundan a una víctima (SYN/UDP/ICMP flood)."""
    set_label("ddos")
    hosts = net.hosts
    victim = random.choice(hosts)
    attackers = [h for h in hosts if h != victim]
    n_attackers = random.randint(2, min(4, len(attackers)))
    chosen_attackers = random.sample(attackers, n_attackers)
    flood_type = random.choice(["--syn", "--udp", "--icmp"])

    _log(f"[ddos] {[a.name for a in chosen_attackers]} -> {victim.IP()} :: {flood_type}")
    for a in chosen_attackers:
        a.cmd(f"hping3 {flood_type} --flood --rand-source -p 80 "
              f"{victim.IP()} >> {LOG_FILE} 2>&1 &")
    time.sleep(duration)
    for a in chosen_attackers:
        a.cmd("pkill -f hping3 2>/dev/null")


# ------------------------------------------------------------------ #
# Orquestador principal
# ------------------------------------------------------------------ #
def generate_dataset(net, total_duration=None, min_phase=None, max_phase=None):
    """
    Ejecuta fases de tráfico intercaladas aleatoriamente hasta cubrir
    total_duration segundos. Ajusta estos valores (o directamente
    config.py) para aproximarte al número de muestras que necesites.
    """
    total_duration = total_duration or config.TOTAL_DURATION
    min_phase = min_phase or config.MIN_PHASE_DURATION
    max_phase = max_phase or config.MAX_PHASE_DURATION

    check_required_tools(net)

    phases = [normal_traffic, scanning_traffic, spoofing_traffic, ddos_traffic]
    elapsed = 0
    while elapsed < total_duration:
        phase = random.choice(phases)
        phase_duration = random.randint(min_phase, max_phase)
        info(f"*** Fase: {phase.__name__} durante {phase_duration}s "
             f"(transcurrido: {elapsed}s / {total_duration}s)\n")
        phase(net, phase_duration)
        elapsed += phase_duration
    set_label("normal")
    info("*** Generación de tráfico finalizada.\n")
