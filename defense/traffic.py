"""
defense/traffic.py
------------------
Generadores de tráfico PURO para la fase de detección y mitigación: cada
función genera un solo tipo de tráfico (normal, ddos, scanning o
spoofing) sin mezclar, para poder evaluar la detección de cada clase por
separado.

Usa las mismas herramientas que la fase de generación del dataset
(ping/iperf para normal, nmap para scanning, hping3 para ddos y
spoofing, arp_spoof.py para ARP), de forma coherente con lo aprendido
allí -mismos flags que funcionaron, sin los bugs que se corrigieron-.
"""
import os
import random
import time

import config

MININET_DIR = os.path.join(config.PROJECT_ROOT, "mininet_lab")
SPOOF_SCRIPT = os.path.join(MININET_DIR, "arp_spoof.py")
PYTHON_BIN = "python3"


def _bg(host, cmd):
    host.cmd(f"{cmd} > /dev/null 2>&1 &")


def normal_traffic(net, duration):
    """Tráfico legítimo: pings e iperf entre hosts al azar."""
    hosts = net.hosts
    end = time.time() + duration
    while time.time() < end:
        h1, h2 = random.sample(hosts, 2)
        variant = random.choice(["ping", "iperf_tcp", "iperf_udp"])
        if variant == "ping":
            h1.cmd(f"ping -c 3 -i 0.3 {h2.IP()} > /dev/null 2>&1")
        elif variant == "iperf_tcp":
            h2.cmd("iperf -s -p 5002 > /dev/null 2>&1 &")
            time.sleep(0.3)
            h1.cmd(f"iperf -c {h2.IP()} -p 5002 -t 2 > /dev/null 2>&1")
        else:
            h2.cmd("iperf -s -u -p 5001 > /dev/null 2>&1 &")
            time.sleep(0.3)
            h1.cmd(f"iperf -c {h2.IP()} -u -p 5001 -b 1M -t 2 > /dev/null 2>&1")
        time.sleep(0.5)


def ddos_traffic(net, duration):
    """DDoS: 2-4 atacantes inundan a una víctima con hping3."""
    hosts = net.hosts
    victim = random.choice(hosts)
    others = [h for h in hosts if h != victim]
    attackers = random.sample(others, random.randint(2, 4))
    flood = random.choice(["--syn", "--udp", "--icmp"])
    port = random.choice([80, 443, 53])
    for a in attackers:
        _bg(a, f"hping3 {flood} --flood -p {port} {victim.IP()}")
    time.sleep(duration)
    for a in attackers:
        a.cmd("pkill -9 -f hping3 2>/dev/null")


def scanning_traffic(net, duration):
    """Scanning: un atacante escanea puertos/hosts con nmap y hping3."""
    hosts = net.hosts
    attacker = random.choice(hosts)
    targets = [h for h in hosts if h != attacker]
    scan_types = ["-sS", "-sT", "-sU --top-ports 8", "-p 1-20", "-p 1-30"]
    timing = ["-T2", "-T3", "-T4"]
    end = time.time() + duration
    while time.time() < end:
        target = random.choice(targets)
        if random.random() < 1 / 6:
            port = random.randint(1, 30)
            attacker.cmd(f"hping3 -A -c 5 -i u200000 -k -s 5099 -p {port} "
                         f"{target.IP()} > /dev/null 2>&1")
        else:
            flags = f"-Pn {random.choice(scan_types)} {random.choice(timing)}"
            attacker.cmd(f"nmap {flags} {target.IP()} > /dev/null 2>&1")
        time.sleep(random.uniform(1, 2))
    attacker.cmd("pkill -9 -f nmap 2>/dev/null")
    attacker.cmd("pkill -9 -f hping3 2>/dev/null")


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
                      f"{attacker.MAC()} {victim_ips}")
        time.sleep(duration)
        attacker.cmd("pkill -9 -f arp_spoof.py 2>/dev/null")
    else:
        victim, fake = random.sample(others, 2)
        port = random.choice([80, 443, 22])
        _bg(attacker, f"hping3 --syn -k -s 5000 -a {fake.IP()} -p {port} "
                      f"-i u20000 {victim.IP()}")
        time.sleep(duration)
        attacker.cmd("pkill -9 -f hping3 2>/dev/null")


GENERATORS = {
    "normal": normal_traffic,
    "ddos": ddos_traffic,
    "scanning": scanning_traffic,
    "spoofing": spoofing_traffic,
}
