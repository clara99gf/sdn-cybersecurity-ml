#!/usr/bin/env bash
# setup.sh
# --------
# Instala TODO lo necesario para este proyecto: paquetes de sistema
# (Mininet, Open vSwitch, nmap, hping3, iperf, ping, python3-venv) y crea
# un entorno virtual con las dependencias Python (ryu, scapy, declaradas
# en setup.py) instaladas junto con el propio proyecto.
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh
#
# (los comandos para EJECUTAR el proyecto, una vez instalado, están en
#  EJECUCION.md)

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
    iputils-ping

echo
echo "=== 2. Creando entorno virtual (venv/) ==="
# --system-site-packages es IMPORTANTE: así el venv puede seguir viendo
# el paquete "mininet" instalado a nivel de sistema (apt), mientras que
# ryu y scapy se instalan solo dentro del venv sin tocar el sistema.
if [ ! -d "venv" ]; then
    python3 -m venv --system-site-packages venv
fi

echo
echo "=== 3. Instalando el proyecto y sus dependencias (pip install -e .) ==="
# Las dependencias (ryu, scapy) están declaradas en setup.py
# (install_requires), así que "pip install -e ." las instala junto con
# el propio proyecto en modo editable -no hace falta un requirements.txt
# aparte-.
# NOTA: PYTHONNOUSERSITE=1 evita que pip dé por satisfecha una dependencia
# presente en ~/.local (instalación de usuario). Garantiza que las librerías
# se instalen explícitamente dentro de venv/, haciéndolas visibles tanto para
# el usuario estándar como para el superusuario (root) al ejecutar con sudo.
export PYTHONNOUSERSITE=1
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -e .

echo
echo "=== 4. Verificando dependencias tal y como se ejecutarán de verdad (con sudo) ==="
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
