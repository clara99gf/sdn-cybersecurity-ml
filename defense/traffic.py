"""
defense/traffic.py
------------------
Generadores de tráfico PURO para la fase de detección y mitigación: cada
función genera un solo tipo de tráfico (normal, ddos, scanning o
spoofing) sin mezclar, para poder evaluar la detección de cada clase por
separado.

Usa las mismas herramientas que la fase de generación del dataset
(ping/iperf para normal, nmap para scanning, hping3 para ddos y
spoofing, arp_spoof.py para ARP).

ROBUSTEZ: cada comando de ataque se envuelve en `timeout` de Linux y se
lanza en segundo plano ('&'), para que NINGUNO pueda bloquear el bucle
ni dejar procesos colgados que atasquen la batería entre fases -era la
causa de que la batería se parara tras la primera o segunda fase-. Al
final de cada fase se hace pkill de las herramientas por si algo quedó.
"""
import os
import random
import time

import config

MININET_DIR = os.path.join(config.PROJECT_ROOT, "mininet_lab")
SPOOF_SCRIPT = os.path.join(MININET_DIR, "arp_spoof.py")
PYTHON_BIN = "python3"


def _bg(host, cmd, max_s=8):
    """Lanza un comando en segundo plano acotado por 'timeout' (para que
    nunca cuelgue) y devuelve el control inmediatamente."""
    host.cmd(f"timeout {max_s} {cmd} > /dev/null 2>&1 &")


def _kill(host, *names):
    for n in names:
        host.cmd(f"pkill -9 -f {n} 2>/dev/null")


def kill_all_attack_procs(net):
    """Mata las herramientas de ataque en TODOS los hosts (no solo en el
    atacante). Importante entre pruebas: un nmap/hping3 que siga en vuelo
    tras terminar una prueba seguiría generando tráfico durante la
    siguiente, dejando la red 'sucia' -era la causa de que, tras el
    scanning, la prueba siguiente no registrara nada-."""
    for h in net.hosts:
        h.cmd("pkill -9 -f nmap 2>/dev/null")
        h.cmd("pkill -9 -f hping3 2>/dev/null")
        h.cmd("pkill -9 -f arp_spoof 2>/dev/null")
        h.cmd("pkill -9 -f iperf 2>/dev/null")


def normal_traffic(net, duration):
    """Tráfico legítimo: MISMAS variantes que en el dataset (ping,
    iperf TCP, iperf UDP con anchos de banda variados). Se reutilizan los
    servidores iperf en vez de crear uno nuevo cada vez -antes se lanzaba
    un 'iperf -s' por iteración y decenas de servidores acumulados
    saturaban los recursos y colgaban la prueba-."""
    hosts = net.hosts
    end = time.time() + duration
    tcp_servers, udp_servers = set(), set()
    while time.time() < end:
        h1, h2 = random.sample(hosts, 2)
        variant = random.choice(["ping", "iperf_tcp", "iperf_udp"])
        if variant == "ping":
            _bg(h1, f"ping -c 3 -i 0.3 {h2.IP()}", max_s=3)
        elif variant == "iperf_tcp":
            if h2.name not in tcp_servers:
                _bg(h2, "iperf -s -p 5002", max_s=int(duration) + 2)
                tcp_servers.add(h2.name)
                time.sleep(0.3)
            _bg(h1, f"iperf -c {h2.IP()} -p 5002 -t 2", max_s=4)
        else:  # iperf_udp con ancho de banda variado (como el dataset)
            bw = random.choice(["200K", "500K", "1M", "5M"])
            if h2.name not in udp_servers:
                _bg(h2, "iperf -s -u -p 5001", max_s=int(duration) + 2)
                udp_servers.add(h2.name)
                time.sleep(0.3)
            _bg(h1, f"iperf -c {h2.IP()} -u -p 5001 -b {bw} -t 2", max_s=4)
        time.sleep(0.5)
    for h in hosts:
        _kill(h, "iperf")

def ddos_traffic(net, duration):
    """DDoS: MISMO tráfico que en la generación del dataset -2-4
    atacantes con hping3 (SYN/UDP/ICMP), puerto origen fijo (-k -s)-.
    Se usan las intensidades ACOTADAS del propio dataset (rate_limited /
    rate_limited_fast, ~500-1000 pps) y no la variante '--flood': el
    flood total satura la CPU y cuelga Mininet, mientras que estas dos
    son las mismas que ya generan tráfico de ddos reconocible por el
    modelo."""
    hosts = net.hosts
    victim = random.choice(hosts)
    attackers = [h for h in hosts if h != victim]
    n_attackers = random.randint(2, min(4, len(attackers)))
    chosen = random.sample(attackers, n_attackers)
    flood_type = random.choice(["--syn", "--udp", "--icmp"])
    rate_flag = random.choice(["-i u2000", "-i u1000"])  # ~500 / ~1000 pps
    target_port = random.choice([80, 443, 22, 53])
    for i, a in enumerate(chosen):
        port = 5100 + i  # puerto origen fijo por atacante (como el dataset)
        _bg(a, f"hping3 {flood_type} -k -s {port} {rate_flag} -p {target_port} "
               f"{victim.IP()}", max_s=int(duration) + 2)
    time.sleep(duration)
    for a in chosen:
        _kill(a, "hping3")
    return [a.IP() for a in chosen]   # IPs de los atacantes (para el % justo)


def _arp_warmup(attacker, targets):
    """Resuelve el ARP entre el atacante y los objetivos ANTES de escanear
    (igual que en la generación del dataset). Así, durante el escaneo, la
    resolución ARP ya está hecha y no domina los sondeos -deja sitio para
    que se capturen las sondas TCP, que son la firma del escaneo-."""
    for t in targets:
        attacker.cmd(f"ping -c 1 -W 1 {t.IP()} > /dev/null 2>&1")


def scanning_traffic(net, duration):
    """Scanning: MISMOS comandos que en el dataset (nmap con varias
    técnicas + sonda ACK hping3), CONCENTRADO en pocos objetivos.

    El modelo detecta scanning por la firma "muchos flujos activos hacia
    los mismos destinos" (flow_count_per_dpid, flows_to_target,
    distinct_sources altos), no por el puerto. Concentrar el escaneo en
    2-3 objetivos (en vez de repartirlo entre los 15) eleva esas features
    lo suficiente para que el modelo lo reconozca, SIN llegar a la
    intensidad que satura Mininet -un escaneo demasiado agresivo (muchos
    nmap concurrentes con rangos enormes) abre cientos de conexiones a la
    vez y desestabiliza la red, cortando la prueba. Este equilibrio
    (concentrado pero moderado) es el que mejor detecta de forma
    estable."""
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    targets = random.sample(others, min(3, len(others)))
    _arp_warmup(attacker, targets)
    scan_types = ["-sS", "-sT", "-sU --top-ports 8", "-p 1-20", "-p 1-30"]
    timing = ["-T2", "-T3", "-T4"]
    ACK_PROBE_PROBABILITY = 1 / 6
    end = time.time() + duration
    while time.time() < end:
        target = random.choice(targets)
        if random.random() < ACK_PROBE_PROBABILITY:
            port = random.randint(1, 30)
            _bg(attacker, f"hping3 -A -c 5 -i u200000 -k -s 5099 -p {port} "
                          f"{target.IP()}", max_s=5)
        else:
            flags = f"-Pn {random.choice(scan_types)} {random.choice(timing)}"
            _bg(attacker, f"nmap {flags} {target.IP()}", max_s=6)
        time.sleep(random.uniform(0.5, 1.0))
    _kill(attacker, "nmap", "hping3")
    return [attacker.IP()]   # IP del atacante (para el % justo)


def spoofing_traffic(net, duration):
    """Spoofing: ARP spoofing multi-víctima o IP spoofing con hping3."""
    hosts = net.hosts
    attacker = random.choice(hosts)
    others = [h for h in hosts if h != attacker]
    if random.random() < 0.5:
        n_victims = random.randint(2, 4)
        picked = random.sample(others, n_victims + 1)
        victims = picked[:n_victims]
        impersonated = picked[n_victims]
        victim_ips = " ".join(v.IP() for v in victims)
        _bg(attacker, f"{PYTHON_BIN} {SPOOF_SCRIPT} {impersonated.IP()} "
                      f"{attacker.MAC()} {victim_ips}", max_s=int(duration) + 2)
        time.sleep(duration)
        _kill(attacker, "arp_spoof.py")
        # Actores: el atacante y la identidad suplantada (los flujos que
        # involucran a estas IPs son el ataque).
        return [attacker.IP(), impersonated.IP()]
    else:
        victim, fake = random.sample(others, 2)
        port = random.choice([80, 443, 22])
        _bg(attacker, f"hping3 --syn -k -s 5000 -a {fake.IP()} -p {port} "
                      f"-i u20000 {victim.IP()}", max_s=int(duration) + 2)
        time.sleep(duration)
        _kill(attacker, "hping3")
        # Actores: el atacante y la IP falsa que usa como origen.
        return [attacker.IP(), fake.IP()]


GENERATORS = {
    "normal": normal_traffic,
    "ddos": ddos_traffic,
    "scanning": scanning_traffic,
    "spoofing": spoofing_traffic,
}
