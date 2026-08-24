#!/usr/bin/env python3
"""
topology.py
-----------
Levanta una topología en árbol en Mininet, la conecta a un controlador
Ryu remoto (sdn_monitor.py) y lanza la generación de tráfico intercalado
para construir el dataset.

Ejecución manual (con el controlador Ryu ya corriendo en otra terminal):
    sudo python3 topology.py

(normalmente no necesitas ejecutar esto directamente: usa run_all.py
en la raíz del proyecto, ver EJECUCION.md)
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.topolib import TreeTopo
from mininet.link import TCLink
from mininet.log import setLogLevel, info

from traffic_generator import generate_dataset


def main():
    setLogLevel("info")

    topo = TreeTopo(depth=config.TOPO_DEPTH, fanout=config.TOPO_FANOUT)
    net = Mininet(topo=topo, link=TCLink, controller=None, autoSetMacs=True)
    net.addController(
        "c0", controller=RemoteController,
        ip=config.RYU_CONTROLLER_IP, port=config.RYU_CONTROLLER_PORT,
    )
    net.start()

    info("*** Esperando a que los switches se conecten al controlador...\n")
    time.sleep(5)

    info("*** Comprobando conectividad básica (pingAll)...\n")
    net.pingAll()

    info("*** Iniciando generación del dataset...\n")
    generate_dataset(
        net,
        total_duration=config.TOTAL_DURATION,
        min_phase=config.MIN_PHASE_DURATION,
        max_phase=config.MAX_PHASE_DURATION,
    )

    info("*** Deteniendo la red...\n")
    net.stop()


if __name__ == "__main__":
    main()
