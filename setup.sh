#!/usr/bin/env bash
# setup.sh
# --------
# Instala TODO lo necesario para este proyecto: paquetes de sistema
# (Mininet, Open vSwitch, nmap, hping3, iperf, python3-venv) y crea un
# entorno virtual con las dependencias Python (ryu, scapy) desde
# requirements.txt.
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh
#
# (los comandos para EJECUTAR el proyecto, una vez instalado, están en
#  EJECUCION.md, no aquí)

set -e

echo "=== 1. Paquetes de sistema (requiere sudo) ==="
sudo apt-get update
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    python3 \
    python3-venv \
    python3-pip \
    nmap \
    hping3 \
    iperf \
    net-tools

echo "=== 2. Creando entorno virtual (venv/) ==="
# --system-site-packages es IMPORTANTE: así el venv puede seguir viendo
# el paquete "mininet" instalado a nivel de sistema (apt), mientras que
# ryu y scapy se instalan solo dentro del venv sin tocar el sistema.
if [ ! -d "venv" ]; then
    python3 -m venv --system-site-packages venv
fi

echo "=== 3. Instalando dependencias Python dentro del venv ==="
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "=== 4. Instalando el proyecto en modo editable (pip install -e .) ==="
./venv/bin/pip install -e .

echo
echo "=== Instalación completa ==="
echo "Si 'pip install ryu' falla por incompatibilidad con tu versión de"
echo "Python (Ryu está poco mantenido y a veces choca con eventlet en"
echo "Python 3.11+), prueba con Python 3.8/3.9 para el venv, o usa el"
echo "fork mantenido 'os-ken' como alternativa (mismo API que ryu)."
echo
echo "Consulta EJECUCION.md para los comandos de arranque."
