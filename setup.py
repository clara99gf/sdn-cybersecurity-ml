#!/usr/bin/env python3
"""
setup.py
--------
Instala el proyecto en modo editable (pip install -e .) dentro del
entorno virtual (lo hace automáticamente setup.sh).

Qué aporta: con la instalación editable, la raíz del proyecto queda en
el sys.path de forma nativa, así que "import config",
"from controller import sdn_monitor", etc. funcionan desde cualquier
sitio -incluido un notebook de preprocesado/entrenamiento fuera de
este árbol de carpetas- sin depender de rutas relativas ni de cwd.

No es estrictamente imprescindible para ejecutar run_all.py (los
scripts del proyecto ya se resuelven solos con un sys.path.insert()
como red de seguridad), pero sí es lo más cómodo y "correcto" en
cuanto quieras reutilizar config.py u otros módulos fuera de
mininet_lab/ o controller/ (por ejemplo, para leer CSV_FILE desde el
notebook donde hagas el preprocesado y entrenamiento).
"""
from setuptools import setup, find_packages

setup(
    name="sdn-tfg-dataset",
    version="1.0.0",
    description=(
        "Generacion de dataset de trafico SDN (normal/scanning/spoofing/ddos) "
        "con Mininet y Ryu, para deteccion de amenazas con Machine Learning."
    ),
    py_modules=["config"],
    packages=find_packages(
        include=["controller", "controller.*", "mininet_lab", "mininet_lab.*"]
    ),
    install_requires=[
        "ryu",
        "scapy",
    ],
    python_requires=">=3.7",
)
