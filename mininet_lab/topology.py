#!/usr/bin/env python3
"""
topology.py
-----------
Levanta la topología en árbol en Mininet, la conecta al controlador Ryu
remoto y lanza la generación de tráfico que construye el dataset.
 
No suele ejecutarse directamente: lo hace run_01_dataset.py, que además
arranca el controlador. Para depurar a mano, con la red y el controlador
reales pero sin generar el dataset, deja libre la CLI de Mininet:
 
    sudo SDN_MANUAL_TEST=1 venv/bin/python3 mininet_lab/topology.py
 
La variable va después de "sudo": sudo descarta por defecto el entorno de
quien lo invoca, así que "VAR=1 sudo ..." no surte efecto.
"""

import os
import subprocess
import sys
import time
from functools import partial

# Permite "import config" sin depender de la instalación editable ni del
# directorio desde el que se ejecute el script.
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topolib import TreeTopo
from mininet.link import TCLink
from mininet.log import setLogLevel, info
from mininet.cli import CLI

from traffic_generator import generate_dataset


def main():
    setLogLevel("info")

    topo = TreeTopo(depth=config.TOPO_DEPTH, fanout=config.TOPO_FANOUT)
    link = partial(TCLink, bw=config.LINK_BANDWIDTH_MBPS)
    # autoSetMacs asigna MACs correlativas y predecibles, lo que permite
    # relacionar cada host con su identidad en el dataset.
    net = Mininet(topo=topo, link=link, controller=None, autoSetMacs=True)
    net.addController(
        "c0", controller=RemoteController,
        ip=config.RYU_CONTROLLER_IP, port=config.RYU_CONTROLLER_PORT,
    )
    net.start()

    # Sin esto las interfaces virtuales agrupan paquetes en super-tramas
    # de hasta 64 KB, y el controlador vería tamaños y tasas que no se
    # corresponden con el tráfico real de la red.
    info("*** Desactivando agregación de paquetes (TSO/GSO/GRO) en interfaces...\n")
    for node in net.hosts + net.switches:
        for intf_name in node.intfNames():
            if intf_name != "lo":
                node.cmd(f"ethtool -K {intf_name} tso off gso off gro off 2>/dev/null")
                # Limita el segmento al MTU estándar de Ethernet.
                node.cmd(f"ip link set dev {intf_name} gso_max_size 1514 2>/dev/null")

    info("*** Esperando a que los switches se conecten al controlador...\n")
    time.sleep(5)

    info("*** Comprobando conectividad básica (pingAll)...\n")
    net.pingAll()

    # Identidades reales tomadas de la API de Mininet.
    # El controlador las lee al arrancar para conocer
    # la vinculación IP/MAC legítima desde el primer paquete.
    info("*** Escribiendo identidades reales de host (IP/MAC) para el "
         "controlador...\n")
    with open(config.HOST_IDENTITY_FILE, "w") as f:
        for host in net.hosts:
            f.write(f"{host.IP()},{host.MAC()}\n")

    # El finally garantiza que la red se detenga y se limpie aunque se
    # interrumpa con Ctrl+C, para no dejar interfaces colgadas.
    try:
        if os.environ.get("SDN_MANUAL_TEST"):
            info("*** SDN_MANUAL_TEST activo: entrando en la CLI de Mininet en vez "
                 "de generar el dataset.\n")
            info("*** Prueba, por ejemplo: h1 nmap -Pn -sS -T4 <IP de h2>\n")
            CLI(net)
        else:
            info("*** Iniciando generación del dataset...\n")
            generate_dataset(
                net,
                total_duration=config.TOTAL_DURATION,
                min_phase=config.MIN_PHASE_DURATION,
                max_phase=config.MAX_PHASE_DURATION,
            )
    except KeyboardInterrupt:
        info("\n*** Interrumpido por el usuario.\n")
    finally:
        info("*** Deteniendo la red...\n")
        net.stop()
        info("*** [topology.py] Limpiando estado residual de Mininet (mn -c)...\n")
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


if __name__ == "__main__":
    main()
