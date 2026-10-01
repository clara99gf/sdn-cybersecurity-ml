#!/usr/bin/env bash
# setup.sh
# --------
# Instalación completa del proyecto con un solo comando, partiendo de una
# máquina Ubuntu limpia. Instala los paquetes de sistema (Mininet, Open
# vSwitch, nmap, hping3, iperf), un Python 3.10 si el sistema no trae uno
# compatible con Ryu (3.8-3.10), y un entorno virtual aislado con las
# dependencias Python y el propio proyecto, aplicando el parche que Ryu
# necesita con eventlet. Termina con una batería de comprobaciones.
#
# Uso:
#   chmod +x setup.sh
#   ./setup.sh                 # versiones exactas de requirements.txt (TFG)
#   PINNED=0 ./setup.sh        # rangos de setup.py (para probar versiones nuevas)
#
# No requiere ningún paso previo ni posterior: si falta Python 3.10 lo
# instala, y si el venv/ existente no sirve lo recrea.
#
# (los comandos para EJECUTAR el proyecto están en EJECUCION.md)

set -e

# PINNED=1 (por defecto): instala las versiones exactas de requirements.txt,
# con las que se obtuvieron los resultados del TFG.
# PINNED=0: deja que pip resuelva dentro de los rangos de setup.py, útil
# para comprobar que el proyecto sigue funcionando con versiones nuevas.
PINNED="${PINNED:-1}"

echo "=== 1. Paquetes de sistema (requiere sudo) ==="
sudo apt-get update
sudo apt-get install -y \
    mininet \
    openvswitch-switch \
    python3 \
    python3-venv \
    python3-pip \
    software-properties-common \
    nmap \
    hping3 \
    iperf \
    iputils-ping

echo
echo "=== 1b. Intérprete de Python compatible con Ryu ==="
# Ryu solo funciona con Python 3.8-3.10: en 3.11+ falla por su
# incompatibilidad con eventlet. Ubuntu 24.04 trae 3.12 como "python3", así
# que en una máquina recién instalada NO hay ningún intérprete válido y hay
# que añadir uno. Se usa el PPA deadsnakes, que publica versiones antiguas
# de Python para Ubuntu.
#
# Se busca SOLO en /usr/bin a propósito: un "python3.9" del PATH puede ser
# el de Anaconda o el de otro gestor de entornos, y entonces el resultado
# dependería de lo que tenga instalado cada usuario. El de /usr/bin es
# siempre el del sistema, igual en todas las máquinas.

find_system_python() {
    for candidate in /usr/bin/python3.10 /usr/bin/python3.9 /usr/bin/python3.8; do
        if [ -x "$candidate" ]; then
            echo "$candidate"
            return 0
        fi
    done
    return 1
}

PYBIN=$(find_system_python || true)

if [ -n "$PYBIN" ]; then
    echo "Encontrado intérprete compatible: $PYBIN"
else
    echo "No hay Python 3.8-3.10 en el sistema. Instalando Python 3.10..."
    if ! sudo add-apt-repository -y ppa:deadsnakes/ppa; then
        echo
        echo "ERROR: no se ha podido añadir el PPA deadsnakes."
        echo "Suele pasar en distribuciones que no son Ubuntu (Debian, Fedora...)."
        echo "Instala manualmente un Python 3.8, 3.9 o 3.10 en /usr/bin y vuelve"
        echo "a ejecutar este script."
        exit 1
    fi
    sudo apt-get update
    sudo apt-get install -y python3.10 python3.10-venv python3.10-distutils

    PYBIN=$(find_system_python || true)
    if [ -z "$PYBIN" ]; then
        echo "ERROR: Python 3.10 no ha quedado instalado en /usr/bin."
        exit 1
    fi
    echo "Instalado: $PYBIN"
fi

echo
echo "=== 2. Entorno virtual (venv/) ==="
# El venv es AISLADO (sin --system-site-packages). Con él, el venv vería los
# paquetes del Python base, y si ese Python es el de Anaconda acaban
# usándose pandas/matplotlib/numpy de Anaconda en lugar de los del venv: el
# entorno deja de ser reproducible porque depende de lo que haya instalado
# en cada máquina.
#
# Un venv/ que no cumpla las condiciones se borra y se rehace.

venv_ok() {
    [ -d "venv" ] || return 1
    [ -x "venv/bin/python3" ] || return 1

    local ver base
    ver=$(./venv/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null) || return 1
    case "$ver" in
        3.8|3.9|3.10) ;;
        *) echo "  - usa Python $ver, incompatible con Ryu"; return 1 ;;
    esac

    if grep -qi "include-system-site-packages *= *true" venv/pyvenv.cfg 2>/dev/null; then
        echo "  - se creó con --system-site-packages (no aislado)"
        return 1
    fi

    base=$(./venv/bin/python3 -c 'import sys; print(sys.base_prefix)' 2>/dev/null) || return 1
    case "$base" in
        *conda*|*Conda*) echo "  - cuelga de Anaconda ($base)"; return 1 ;;
    esac

    return 0
}

if [ -d "venv" ]; then
    if venv_ok; then
        echo "venv/ existente es válido: se reutiliza."
    else
        echo "El venv/ existente no sirve (motivos arriba). Se recrea."
        rm -rf venv
    fi
fi

if [ ! -d "venv" ]; then
    echo "Creando entorno virtual aislado con $PYBIN."
    "$PYBIN" -m venv venv
    # Restos de instalaciones editables anteriores: si se quedan, pip puede
    # reutilizar metadatos viejos del proyecto.
    rm -rf ./*.egg-info build dist .eggs
fi

PYVER=$(./venv/bin/python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')
echo "Python del entorno: $PYVER"

echo
echo "=== 2b. Dando acceso a Mininet dentro del venv ==="
# Mininet se instala con apt, no con pip, y queda en los dist-packages del
# Python del sistema (3.12 en Ubuntu 24.04), que NO es el del venv. En vez
# de abrir el venv entero con --system-site-packages, se enlaza únicamente
# el paquete "mininet": así entra eso y nada más.
#
# Es seguro porque Mininet es Python puro (sin extensiones compiladas), de
# modo que un paquete instalado para 3.12 se importa igual desde 3.10.
MININET_DIR=$(/usr/bin/python3 -c \
    "import mininet, os; print(os.path.dirname(mininet.__file__))" 2>/dev/null || true)

if [ -z "$MININET_DIR" ]; then
    echo "AVISO: no se ha localizado el paquete Python de Mininet."
    echo "Comprueba que 'mininet' se instaló correctamente con apt."
else
    VENV_SITE=$(./venv/bin/python3 -c \
        "import sysconfig; print(sysconfig.get_paths()['purelib'])")
    ln -sfn "$MININET_DIR" "$VENV_SITE/mininet"
    echo "Enlazado: $VENV_SITE/mininet -> $MININET_DIR"
fi

echo
echo "=== 3. Dependencias Python y proyecto ==="
# PYTHONNOUSERSITE=1 evita que pip dé por satisfecha una dependencia
# presente en ~/.local: fuerza que todo quede dentro de venv/, visible
# tanto para el usuario normal como para root (al ejecutar con sudo).
export PYTHONNOUSERSITE=1
./venv/bin/pip install --upgrade pip

echo
echo "--- 3a. Ryu (instalación especial) ---"
# Ryu 4.34 (2019) no compila con las versiones modernas de setuptools: su
# build usa una API que setuptools ya no incluye. Se fija setuptools
# 58.1.0 (la última que la soporta) y se instala Ryu con
# --no-build-isolation para que use esa setuptools y no la que pip
# descargaría en un entorno de build aparte. pbr, la dependencia de build
# de Ryu, se instala antes porque al desactivar el aislamiento pip ya no
# la trae sola. eventlet se fija por el mismo motivo (ver paso 3c).
./venv/bin/pip install "setuptools==58.1.0" wheel pbr
./venv/bin/pip install --no-build-isolation "ryu==4.34" "eventlet<0.36"

echo
echo "--- 3b. Resto de dependencias y proyecto ---"
# Dos modos:
#   PINNED=1 -> versiones exactas de requirements.txt (entorno del TFG).
#               Solo se aplica con Python 3.10, porque esos pines se
#               generaron con esa versión; el paso 1b instala 3.10 cuando
#               hace falta, así que es el caso normal.
#   PINNED=0 -> rangos declarados en setup.py, resueltos por pip.
USE_PINNED=0
if [ "$PINNED" = "1" ]; then
    if [ "$PYVER" = "3.10" ] && [ -f "requirements.txt" ]; then
        USE_PINNED=1
    elif [ "$PYVER" != "3.10" ]; then
        echo "AVISO: requirements.txt fija versiones que requieren Python 3.10,"
        echo "y este entorno es $PYVER (había un intérprete antiguo en el"
        echo "sistema y se ha reutilizado). Se instalarán los rangos de"
        echo "setup.py: el proyecto funcionará, pero el entorno no será"
        echo "idéntico al del TFG."
    fi
fi

if [ "$USE_PINNED" -eq 1 ]; then
    echo "Modo reproducible: versiones exactas de requirements.txt."
    ./venv/bin/pip install -r requirements.txt
    # --no-deps porque requirements.txt ya ha resuelto el árbol completo;
    # aquí solo se instala el proyecto en modo editable.
    ./venv/bin/pip install -e . --no-deps
else
    echo "Modo flexible: rangos declarados en setup.py."
    ./venv/bin/pip install -e .
fi

echo
echo "=== 3c. Parcheando ryu/app/wsgi.py (compatibilidad con eventlet) ==="
# Ryu importa de eventlet.wsgi un símbolo que las versiones de eventlet
# compatibles ya no exportan, y sin este parche no arranca. El parche
# envuelve ese import en un try/except. La ruta de wsgi.py se localiza con
# importlib.util.find_spec (que no ejecuta el módulo) y no importándolo,
# porque ese import es justo el que falla antes del parche. Se aplica sobre
# un fichero del venv (no versionado), así que se repite en cada
# instalación; es idempotente.
./venv/bin/python3 - <<'PYEOF'
import importlib.util
import os
import sys

spec = importlib.util.find_spec("ryu")
if spec is None or not spec.origin:
    print("[!] No se ha encontrado el paquete ryu en el venv.")
    sys.exit(1)

path = os.path.join(os.path.dirname(spec.origin), "app", "wsgi.py")
if not os.path.exists(path):
    print("[!] No existe %s" % path)
    sys.exit(1)

with open(path) as f:
    lines = f.readlines()

if any("ALREADY_HANDLED = None" in line for line in lines):
    print("[=] wsgi.py ya estaba parcheado.")
    sys.exit(0)

# Se respeta la indentación real de la línea encontrada, en lugar de
# suponerla: así el parche no depende de dónde esté el import dentro del
# fichero (nivel de clase, de método, etc.).
out = []
patched = False
for line in lines:
    if not patched and "from eventlet.wsgi import ALREADY_HANDLED" in line:
        indent = line[:len(line) - len(line.lstrip())]
        out.append(indent + "try:\n")
        out.append(indent + "    from eventlet.wsgi import ALREADY_HANDLED\n")
        out.append(indent + "except ImportError:\n")
        out.append(indent + "    ALREADY_HANDLED = None\n")
        patched = True
    else:
        out.append(line)

if patched:
    with open(path, "w") as f:
        f.writelines(out)
    print("[+] wsgi.py parcheado correctamente.")
else:
    print("[!] No se encontró el import esperado en wsgi.py; puede que esta "
          "versión de Ryu no lo necesite. Revisa si ryu-manager arranca.")
PYEOF

echo
echo "=== 4. Comprobaciones finales ==="
FALLOS=0

check() {
    # $1 = descripción, $2 = comando
    if eval "$2" >/dev/null 2>&1; then
        echo "  OK     $1"
    else
        echo "  FALLO  $1"
        echo "         Reproduce el error con: $2"
        FALLOS=$((FALLOS + 1))
    fi
}

# Las fases 1 y 3 (run_01_dataset.py, run_03_defense.py) se ejecutan con
# sudo, así que se comprueban también en ese contexto.
check "import mininet" \
      "./venv/bin/python3 -c 'import mininet'"
check "import scapy" \
      "./venv/bin/python3 -c 'import scapy'"
check "import ryu.app.wsgi (parche aplicado)" \
      "./venv/bin/python3 -c 'import ryu.app.wsgi'"
check "import sklearn, pandas, numpy, matplotlib" \
      "./venv/bin/python3 -c 'import sklearn, pandas, numpy, matplotlib'"
check "ryu-manager arranca" \
      "./venv/bin/ryu-manager --version"
check "scapy visible con sudo" \
      "sudo env PYTHONNOUSERSITE=1 ./venv/bin/python3 -c 'import scapy'"
check "mininet visible con sudo" \
      "sudo env PYTHONNOUSERSITE=1 ./venv/bin/python3 -c 'import mininet'"

echo
# Aviso si alguna dependencia se está resolviendo fuera del venv: señal de
# que el aislamiento no es completo y el entorno no sería reproducible.
./venv/bin/python3 - <<'PYEOF'
import matplotlib
import numpy
import pandas
import sklearn

fuera = []
for mod in (numpy, pandas, sklearn, matplotlib):
    if "venv" not in mod.__file__:
        fuera.append("%s -> %s" % (mod.__name__, mod.__file__))

if fuera:
    print("AVISO: estas dependencias NO vienen del venv:")
    for linea in fuera:
        print("  " + linea)
    print("El entorno no es reproducible. Revisa que venv/ sea aislado.")
else:
    print("OK: todas las dependencias se resuelven dentro del venv.")
PYEOF

echo
if [ "$FALLOS" -eq 0 ]; then
    echo "=== Instalación completa ==="
    echo "Consulta EJECUCION.md para los comandos de arranque."
else
    echo "=== Instalación terminada con $FALLOS comprobación(es) fallida(s) ==="
    echo "Revisa los mensajes de arriba antes de ejecutar el proyecto."
    exit 1
fi