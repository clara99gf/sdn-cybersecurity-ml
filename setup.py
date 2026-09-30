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
        "Random Forest) para detección de amenazas."
    ),
    py_modules=["config", "feature_windows"],
    packages=find_packages(
        include=["controller", "controller.*", "mininet_lab", "mininet_lab.*",
                 "ml", "ml.*", "defense", "defense.*"]
    ),
    install_requires=[
        # Generación del dataset (Mininet/Ryu). eventlet se fija porque
        # las versiones recientes rompen Ryu (setup.sh aplica además un
        # parche a ryu/app/wsgi.py por el mismo motivo).
        "ryu",
        "eventlet<0.36",
        "scapy",
        # Preprocesado / entrenamiento / evaluación (ml/)
        "scikit-learn",
        "pandas",
        "numpy<2",
        "matplotlib",
        "joblib",
        # Fase de detección/mitigación: % CPU del proceso Ryu para la
        # gráfica de impacto en infraestructura. Si no está, el
        # controlador funciona igual pero no registra CPU.
        "psutil",
    ],
    # Ryu (poco mantenido) no funciona en Python 3.11+ por su
    # incompatibilidad con eventlet. El entorno de referencia es 3.10.
    python_requires=">=3.8,<3.11",
)
