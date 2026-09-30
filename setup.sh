#!/usr/bin/env bash
# setup.sh
# --------
# Instala TODO lo necesario para el proyecto con un solo comando:
# paquetes de sistema (Mininet, Open vSwitch, nmap, hping3, iperf, ping)
# y un entorno virtual con las dependencias Python (ryu, scapy,
# scikit-learn, etc.) instaladas junto con el propio proyecto.
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
# --system-site-packages permite que el venv vea el paquete "mininet"
# instalado por apt; el resto de dependencias se instalan dentro del venv.
if [ ! -d "venv" ]; then
    python3 -m venv --system-site-packages venv
fi

echo
echo "=== 3. Instalando el proyecto y sus dependencias (pip install -e .) ==="
# Todas las dependencias Python (ryu, eventlet, scapy, scikit-learn...)
# están declaradas en setup.py, así que "pip install -e ." las instala en
# el venv junto con el propio proyecto en modo editable.
# PYTHONNOUSERSITE=1 evita que pip dé por satisfecha una dependencia
# presente en ~/.local: fuerza que todo quede dentro de venv/, visible
# tanto para el usuario normal como para root (al ejecutar con sudo).
export PYTHONNOUSERSITE=1
./venv/bin/pip install --upgrade pip
./venv/bin/pip install -e .

echo
echo "=== 3b. Forzando numpy/scipy/scikit-learn compatibles dentro del venv ==="
# --system-site-packages puede hacer que se "vea" un scipy del sistema
# compilado para otra versión de numpy (incompatibilidad binaria). Se
# fuerza que las tres vengan del venv, resueltas juntas y compatibles.
./venv/bin/pip install --force-reinstall --no-deps "numpy<2" scipy scikit-learn

echo
echo "=== 3c. Asegurando psutil dentro del venv (fase 3: CPU de Ryu) ==="
# psutil ya está en setup.py, pero al ejecutar el controlador de defensa
# con sudo --system-site-packages puede impedir verlo si quedó solo a
# nivel de usuario. Se fuerza dentro del venv.
./venv/bin/pip install --force-reinstall --no-deps psutil

echo
echo "=== 3d. Parcheando ryu/app/wsgi.py (compatibilidad con eventlet) ==="
# Ryu importa ALREADY_HANDLED de eventlet.wsgi, símbolo que las versiones
# recientes de eventlet ya no exportan, y sin este parche Ryu no arranca.
# El parche envuelve ese import en un try/except. La ruta del fichero se
# localiza preguntándole al Python del venv dónde está instalado Ryu, para
# no depender de la versión concreta de Python.
./venv/bin/python3 - <<'PYEOF'
import os
import ryu.app.wsgi as m

path = m.__file__
with open(path) as f:
    text = f.read()

target = "        from eventlet.wsgi import ALREADY_HANDLED\n"
patched = (
    "        try:\n"
    "            from eventlet.wsgi import ALREADY_HANDLED\n"
    "        except ImportError:\n"
    "            ALREADY_HANDLED = None\n"
)

if "except ImportError:" in text and "ALREADY_HANDLED = None" in text:
    print("[=] wsgi.py ya estaba parcheado.")
elif target in text:
    with open(path, "w") as f:
        f.write(text.replace(target, patched))
    print("[+] wsgi.py parcheado correctamente.")
else:
    print("[!] No se encontró el import esperado en wsgi.py; puede que esta "
          "versión de Ryu no lo necesite. Revisa si ryu-manager arranca.")
PYEOF

echo
echo "=== 4. Verificando que scapy es visible ejecutando con sudo ==="
# Así es como corren las fases 1 y 3 (run_01_dataset.py, run_03_defense.py).
if sudo env PYTHONNOUSERSITE=1 ./venv/bin/python3 -c "import scapy" 2>/dev/null; then
    echo "OK: scapy es visible con sudo."
else
    echo "AVISO: scapy no es visible con sudo. Forzando reinstalación en el venv..."
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
echo "=== 5. Comprobación final: ryu-manager arranca ==="
if ./venv/bin/ryu-manager --version >/dev/null 2>&1; then
    echo "OK: ryu-manager funciona ($(./venv/bin/ryu-manager --version 2>&1))."
else
    echo "AVISO: ryu-manager no arranca. Si el error viene de eventlet, revisa"
    echo "el paso 3d. Ryu solo es compatible con Python 3.8-3.10."
fi

echo
echo "=== Instalación completa ==="
echo "Consulta EJECUCION.md para los comandos de arranque."
