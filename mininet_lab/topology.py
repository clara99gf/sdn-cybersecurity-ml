#!/usr/bin/env python3
"""
topology.py
-----------
Levanta una topología en árbol en Mininet, la conecta a un controlador
Ryu remoto (sdn_monitor.py) y lanza la generación de tráfico intercalado
para construir el dataset.

Ejecución (con el controlador Ryu ya corriendo en otra terminal):
    sudo python3 topology.py

Modo prueba manual (para depurar a mano, con la red y el controlador
REALES -misma topología, mismos ajustes TSO/GSO/GRO- pero SIN lanzar la
generación automática de tráfico, dejando la CLI de Mininet libre):
    sudo SDN_MANUAL_TEST=1 venv/bin/python3 mininet_lab/topology.py

(el orden importa: la variable va DESPUÉS de "sudo", no antes -sudo
borra el entorno de quien lo llama por defecto, así que "VAR=1 sudo
..." no funciona, tiene que ser "sudo VAR=1 ..."-.

(normalmente no se necesita ejecutar esto directamente: se usa run_01_dataset.py
en la raíz del proyecto, ver EJECUCION.md)
"""

import os
import subprocess
import sys
import time
from functools import partial

# Red de seguridad: si por lo que sea "pip install -e ." no está hecho
# (o el venv se rehízo sin volver a ejecutarlo), esto asegura que
# "import config" se resuelva igualmente sin depender de la instalación
# editable ni de la carpeta desde la que se ejecute este script.
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
    net = Mininet(topo=topo, link=link, controller=None, autoSetMacs=True)
    net.addController(
        "c0", controller=RemoteController,
        ip=config.RYU_CONTROLLER_IP, port=config.RYU_CONTROLLER_PORT,
    )
    net.start()

    info("*** Desactivando agregación de paquetes (TSO/GSO/GRO) en interfaces...\n")
    for node in net.hosts + net.switches:
        for intf_name in node.intfNames():
            if intf_name != "lo":
                # Desactiva offloading para evitar super-tramas no realistas
                node.cmd(f"ethtool -K {intf_name} tso off gso off gro off 2>/dev/null")
                # Limita el tamaño de segmento al MTU estándar de Ethernet (1514B)
                node.cmd(f"ip link set dev {intf_name} gso_max_size 1514 2>/dev/null")

    info("*** Esperando a que los switches se conecten al controlador...\n")
    time.sleep(5)

    info("*** Comprobando conectividad básica (pingAll)...\n")
    net.pingAll()

    # try/finally: igual que ya hace run_01_dataset.py -si se interrumpe
    # con Ctrl+C (frecuente en el modo de prueba manual, CLI incluida) o
    # falla algo, net.stop() y "mn -c" se ejecutan de todas formas, sin
    # dejar interfaces de red colgadas para la siguiente vez.
    try:
        if os.environ.get("SDN_MANUAL_TEST"):
            info("*** SDN_MANUAL_TEST activo: entrando en la CLI de Mininet en vez "
                 "de generar el dataset -red y controlador reales, para probar "
                 "comandos a mano (p.ej. nmap) en el entorno de verdad-.\n")
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
