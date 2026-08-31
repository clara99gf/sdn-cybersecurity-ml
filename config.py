#!/usr/bin/env python3
"""
config.py
---------
Configuración centralizada del proyecto. Todos los módulos importan este fichero
para no duplicar rutas ni parámetros.
"""
import os

# Desactiva los paquetes instalados a nivel de usuario (~/.local)
# para evitar que interfieran con las librerías del entorno virtual.
os.environ.setdefault("PYTHONNOUSERSITE", "1")

# --------------------------------------------------------------- #
# Rutas del proyecto
# --------------------------------------------------------------- #
PROJECT_ROOT = os.path.dirname(os.path.abspath(__file__))
MININET_LAB_DIR = os.path.join(PROJECT_ROOT, "mininet_lab")
CONTROLLER_DIR = os.path.join(PROJECT_ROOT, "controller")

SPOOF_SCRIPT = os.path.join(MININET_LAB_DIR, "arp_spoof.py")
CONTROLLER_SCRIPT = os.path.join(CONTROLLER_DIR, "sdn_monitor.py")

VENV_DIR = os.path.join(PROJECT_ROOT, "venv")
VENV_PYTHON = os.path.join(VENV_DIR, "bin", "python3")
VENV_RYU_MANAGER = os.path.join(VENV_DIR, "bin", "ryu-manager")

# Python que se usará dentro de los hosts de Mininet para lanzar
# arp_spoof.py. Se utiliza el intérprete del entorno virtual
# si está disponible; en caso contrario, se utiliza el python3 del sistema.
PYTHON_BIN = VENV_PYTHON if os.path.exists(VENV_PYTHON) else "python3"

# Se utiliza el ejecutable del entorno virtual
# si está disponible; en caso contrario, se utiliza el ryu-manager del sistema.
RYU_MANAGER_BIN = VENV_RYU_MANAGER if os.path.exists(VENV_RYU_MANAGER) else "ryu-manager"

# --------------------------------------------------------------- #
# Ficheros compartidos / logs / dataset
# --------------------------------------------------------------- #
# Directorios del proyecto para almacenar datos, logs y ficheros
# generados durante la ejecución.
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime") 

# Crea los directorios si no existen
for _d in (DATA_DIR, LOGS_DIR, RUNTIME_DIR):
    os.makedirs(_d, exist_ok=True)

LABEL_FILE = os.path.join(RUNTIME_DIR, "current_label.txt")
FLUSH_REQUEST_FILE = os.path.join(RUNTIME_DIR, "flush_request.txt")
CSV_FILE = os.path.join(DATA_DIR, "dataset_sdn.csv")
RYU_LOG_FILE = os.path.join(LOGS_DIR, "ryu_controller.log")
TRAFFIC_LOG_FILE = os.path.join(LOGS_DIR, "traffic_generator.log")

# --------------------------------------------------------------- #
# Controlador Ryu / OpenFlow
# --------------------------------------------------------------- #
RYU_CONTROLLER_IP = "127.0.0.1"
RYU_CONTROLLER_PORT = 6653

POLL_INTERVAL = 2           # Intervalo entre solicitudes de estadísticas de flujo al switch (segundos)
FLOW_IDLE_TIMEOUT = 3       # Tiempo de inactividad tras el cual se elimina un flujo (segundos)
FLOW_HARD_TIMEOUT = 10      # Tiempo máximo de permanencia de un flujo en el switch (segundos)

# --------------------------------------------------------------- #
# Topología Mininet
# --------------------------------------------------------------- #
TOPO_DEPTH = 2              # Profundidad de la topología en árbol
TOPO_FANOUT = 4             # Número máximo de nodos hijos por cada nodo del árbol

# Ancho de banda (Mbps) de cada enlace virtual.
LINK_BANDWIDTH_MBPS = 10

# --------------------------------------------------------------- #
# Generación de tráfico
# --------------------------------------------------------------- #
# Número objetivo de filas del dataset
TARGET_ROWS = 30000

# Duración máxima de la generación de tráfico (segundos)
TOTAL_DURATION = 4500

# Duración mínima y máxima de cada fase de tráfico (segundos)
MIN_PHASE_DURATION = 10         
MAX_PHASE_DURATION = 25

# Límite de filas que puede aportar UNA SOLA fase
MAX_ROWS_PER_PHASE = 1500

# Tiempo de espera entre fases para permitir que finalice el tráfico anterior (segundos)
PHASE_SETTLE_SECONDS = 1.5

# Tiempo de espera antes de iniciar la primera fase (segundos)
STARTUP_SETTLE_SECONDS = FLOW_IDLE_TIMEOUT + 2

# Si es True, al arrancar el controlador se limpia cualquier
# data/dataset_sdn.csv previo y se empieza uno nuevo en limpio.
RESET_DATASET_ON_START = True

# Qué hacer con el CSV anterior al resetear: True lo archiva con
# timestamp (dataset_sdn_20260824_153000.csv); False lo borra sin más,
# para tener siempre un único data/dataset_sdn.csv.
ARCHIVE_PREVIOUS_DATASET = False

# Indica si las filas generadas durante la fase inicial de calentamiento se almacenan
WRITE_WARMUP_ROWS = True
