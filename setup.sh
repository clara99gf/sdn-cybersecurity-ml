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
# PYTHONNOUSERSITE=1 evita que pip dé por "ya satisfecha" una
# dependencia que solo esté instalada en ~/.local (instalación por
# usuario) en vez de dentro del propio venv/. Sin esto, un paquete
# como scapy podía quedar visible cuando lo pruebas como tu usuario
# normal, pero NO visible para los procesos que corren con sudo
# (root tiene su propio ~/.local, distinto del tuyo).
export PYTHONNOUSERSITE=1
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -r requirements.txt

echo "=== 4. Instalando el proyecto en modo editable (pip install -e .) ==="
./venv/bin/pip install -e .

echo "=== 5. Verificando dependencias tal y como se ejecutarán de verdad (con sudo) ==="
# El pipeline entero corre con sudo (Mininet lo requiere), y con sudo
# el $HOME suele pasar a ser /root -distinto del tuyo-. Un paquete que
# se ve bien al probarlo como tu usuario normal puede seguir sin verse
# para el proceso real. Lo comprobamos aquí mismo, en las mismas
# condiciones en las que luego se ejecutará run_all.py (por eso el
# "sudo" en la comprobación). La REINSTALACIÓN, en cambio, se hace SIN
# sudo: el venv/ es tuyo, y usar sudo ahí dejaría archivos propiedad de
# root dentro que luego te den "Permission denied" al hacer tú un pip
# install normal.
if sudo env PYTHONNOUSERSITE=1 ./venv/bin/python3 -c "import scapy" 2>/dev/null; then
    echo "OK: scapy es visible ejecutando con sudo."
else
    echo "AVISO: scapy NO es visible ejecutando con sudo (así es como corre"
    echo "run_all.py). Forzando reinstalación dentro del propio venv..."
    ./venv/bin/pip install --force-reinstall --no-deps --ignore-installed scapy
    if sudo env PYTHONNOUSERSITE=1 ./venv/bin/python3 -c "import scapy" 2>/dev/null; then
        echo "OK: solucionado."
    else
        echo "ERROR: scapy sigue sin verse con sudo. Ejecuta esto para ver el"
        echo "error exacto y compártelo:"
        echo "  sudo env PYTHONNOUSERSITE=1 venv/bin/python3 -c \"import sys; print(sys.executable); print(sys.path); import scapy\""
    fi
fi

echo
echo "=== Instalación completa ==="
echo "Si 'pip install ryu' falla por incompatibilidad con tu versión de"
echo "Python (Ryu está poco mantenido y a veces choca con eventlet en"
echo "Python 3.11+), prueba con Python 3.8/3.9 para el venv, o usa el"
echo "fork mantenido 'os-ken' como alternativa (mismo API que ryu)."
echo
echo "Consulta EJECUCION.md para los comandos de arranque."
