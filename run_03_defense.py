#!/usr/bin/env python3
"""
run_03_defense.py
-----------------
Orquestador de la FASE DE DETECCIÓN Y MITIGACIÓN (tercera fase del TFG).

Menú interactivo en terminal que permite:
  - Lanzar tráfico de UN tipo (normal / ddos / scanning / spoofing) y ver
    cómo el controlador lo detecta y mitiga en vivo.
  - Lanzar la BATERÍA COMPLETA: los cuatro tipos en secuencia, con estado
    limpio entre cada uno, y generar todas las gráficas al final.
  - Generar las gráficas a partir de las métricas ya recogidas.
  - Salir limpiando el entorno (mn -c, matar Ryu).

Levanta por su cuenta el controlador de defensa (controller/sdn_defense.py)
y la topología Mininet, igual que run_01_dataset.py hace con la de
generación. Requiere sudo (Mininet).

Uso:
    sudo venv/bin/python3 run_03_defense.py
"""
import os
import signal
import subprocess
import sys
import time
from functools import partial

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

CONTROLLER = os.path.join("controller", "sdn_defense.py")
EVENTS_CSV = os.path.join(config.PROJECT_ROOT, "metrics", "defense_events.csv")

# Duración por defecto de cada prueba de tráfico (segundos).
PHASE_DURATION = 30


# --------------------------------------------------------------------- #
# Arranque y parada del entorno
# --------------------------------------------------------------------- #
def _start_controller():
    ryu = _find_ryu_manager()
    print(f"*** Arrancando el controlador de defensa ({ryu})...")
    proc = subprocess.Popen(
        [ryu, CONTROLLER],
        stdout=open(os.path.join(config.LOGS_DIR, "ryu_defense.log"), "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    # esperar a que Ryu escuche
    for _ in range(30):
        if _port_open(config.RYU_CONTROLLER_IP, config.RYU_CONTROLLER_PORT):
            break
        time.sleep(0.5)
    print("*** Controlador listo.")
    return proc


def _find_ryu_manager():
    venv = os.path.join(config.PROJECT_ROOT, "venv", "bin", "ryu-manager")
    return venv if os.path.exists(venv) else "ryu-manager"


def _port_open(ip, port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((ip, port)) == 0


def _build_net():
    from mininet.net import Mininet
    from mininet.node import RemoteController
    from mininet.topolib import TreeTopo
    from mininet.link import TCLink

    topo = TreeTopo(depth=config.TOPO_DEPTH, fanout=config.TOPO_FANOUT)
    link = partial(TCLink, bw=config.LINK_BANDWIDTH_MBPS)
    net = Mininet(topo=topo, link=link, controller=None, autoSetMacs=True)
    net.addController("c0", controller=RemoteController,
                      ip=config.RYU_CONTROLLER_IP, port=config.RYU_CONTROLLER_PORT)
    net.start()
    for node in net.hosts + net.switches:
        for intf in node.intfNames():
            if intf != "lo":
                node.cmd(f"ethtool -K {intf} tso off gso off gro off 2>/dev/null")
    time.sleep(3)
    net.pingAll()
    # Escribir las identidades reales IP/MAC de los hosts, igual que hace
    # topology.py en la fase 1: el controlador de defensa las carga para
    # sembrar la detección de spoofing con la verdad de referencia desde
    # el arranque. Se hace aquí para no depender de que la fase 1 se haya
    # ejecutado antes (Mininet asigna las mismas IPs/MACs, pero el archivo
    # podría no existir en una instalación limpia).
    with open(config.HOST_IDENTITY_FILE, "w") as f:
        for host in net.hosts:
            f.write(f"{host.IP()},{host.MAC()}\n")
    return net


def _cleanup(controller_proc=None, net=None):
    print("\n*** Limpiando entorno...")
    if net is not None:
        try:
            net.stop()
        except Exception:
            pass
    if controller_proc is not None:
        try:
            os.killpg(os.getpgid(controller_proc.pid), signal.SIGTERM)
        except Exception:
            pass
    subprocess.run(["pkill", "-f", "sdn_defense.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("*** Entorno limpio (mn -c ejecutado).")


# --------------------------------------------------------------------- #
# Pruebas de tráfico
# --------------------------------------------------------------------- #
def _run_single(net, kind, duration=PHASE_DURATION):
    from defense import traffic
    print(f"\n*** Generando tráfico '{kind}' durante {duration}s...")
    print("    (el controlador clasifica y mitiga en vivo; métricas -> "
          "metrics/defense_events.csv)")
    traffic.GENERATORS[kind](net, duration)
    print(f"*** Prueba '{kind}' terminada.")


def _run_battery(net):
    print("\n=== BATERÍA COMPLETA: normal -> scanning -> ddos -> spoofing ===")
    for kind in ["normal", "scanning", "ddos", "spoofing"]:
        _run_single(net, kind)
        _drain(3)  # dejar que las últimas estadísticas se procesen
    print("\n=== Batería completa terminada. Generando gráficas... ===")
    _make_plots()


def _drain(seconds):
    time.sleep(seconds)


def _make_plots():
    from defense import plots
    plots.generate_all(EVENTS_CSV)


# --------------------------------------------------------------------- #
# Menú
# --------------------------------------------------------------------- #
MENU = """
============================================================
  FASE 3 - DETECCIÓN Y MITIGACIÓN (menú)
============================================================
  1) Tráfico NORMAL   (no debería mitigarse)
  2) Tráfico SCANNING (nmap)
  3) Tráfico DDOS     (hping3)
  4) Tráfico SPOOFING (ARP / IP)
  5) BATERÍA COMPLETA (los 4 en secuencia + gráficas)
  6) Generar gráficas con las métricas actuales
  7) Salir (limpia el entorno: mn -c)
============================================================
"""


def main():
    if os.geteuid() != 0:
        print("Este script necesita sudo (Mininet).")
        sys.exit(1)

    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    controller_proc = _start_controller()
    net = None
    try:
        net = _build_net()
        print("*** Red lista. El controlador de defensa está clasificando en vivo.")
        while True:
            print(MENU)
            choice = input("Elige una opción [1-7]: ").strip()
            if choice == "1":
                _run_single(net, "normal")
            elif choice == "2":
                _run_single(net, "scanning")
            elif choice == "3":
                _run_single(net, "ddos")
            elif choice == "4":
                _run_single(net, "spoofing")
            elif choice == "5":
                _run_battery(net)
            elif choice == "6":
                _make_plots()
            elif choice == "7":
                break
            else:
                print("Opción no válida.")
    except KeyboardInterrupt:
        print("\n*** Interrumpido por el usuario.")
    finally:
        _cleanup(controller_proc, net)
        print("\n*** Fin de la fase de detección y mitigación.")
        print(f"    Métricas: {EVENTS_CSV}")
        print(f"    Gráficas: {os.path.join('results', 'figures', 'defense')}")


if __name__ == "__main__":
    main()
