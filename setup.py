#!/usr/bin/env python3
"""
setup.py
--------
Instala el proyecto en modo editable (pip install -e .) dentro del
entorno virtual (lo hace automáticamente setup.sh).

Qué aporta: con la instalación editable, la raíz del proyecto queda en
el sys.path de forma nativa, así que "import config",
"from controller import sdn_monitor", etc. funcionan desde cualquier
sitio sin depender de rutas relativas ni de cwd.
"""
from setuptools import setup, find_packages

setup(
    name="sdn-cybersecurity-ml",
    version="1.0.0",
    description=(
        "Generacion de dataset de trafico SDN (normal/scanning/spoofing/ddos) "
        "con Mininet y Ryu, mas preprocesado/entrenamiento/evaluacion de "
        "modelos de Machine Learning (Logistic Regression, Decision Tree, "
        "Random Forest) para deteccion de amenazas."
    ),
    py_modules=["config", "feature_windows"],
    packages=find_packages(
        include=["controller", "controller.*", "mininet_lab", "mininet_lab.*",
                 "ml", "ml.*", "defense", "defense.*"]
    ),
    install_requires=[
        # Generación del dataset (Mininet/Ryu)
        "ryu",
        "scapy",
        # Preprocesado / entrenamiento / evaluación (ml/)
        "scikit-learn",
        "pandas",
        "numpy",
        "matplotlib",
        "joblib",
        # Fase de detección/mitigación: % CPU del proceso Ryu para la
        # gráfica de impacto en infraestructura. Si no está, el
        # controlador funciona igual pero no registra CPU.
        "psutil",
    ],
    python_requires=">=3.7",
)
