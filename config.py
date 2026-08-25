#!/usr/bin/env python3
"""
config.py
---------
Configuración centralizada del proyecto. Todos los módulos
(controller/sdn_monitor.py, mininet_lab/topology.py,
mininet_lab/traffic_generator.py, run_all.py) importan este fichero
para no duplicar rutas ni parámetros.

Cambia aquí lo que necesites ajustar (duración, nº de hosts,
POLL_INTERVAL, rutas, etc.) en lugar de tocar varios archivos.
"""
import os

# Evita que Python consulte el "user site-packages" (~/.local/lib/...)
# al resolver imports. Es clave para procesos que corren con sudo: su
# $HOME suele pasar a ser /root, así que un paquete instalado con
# --user bajo tu usuario normal (p.ej. scapy en ~/.local de "clara")
# es invisible para el mismo intérprete ejecutado como root, aunque
# "pip show" lo encuentre perfectamente cuando lo compruebas tú mismo.
# Fijar esto ANTES de que nada importe módulos de terceros asegura que
# solo se usen los paquetes instalados dentro del propio venv/.
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

# Python que se usará DENTRO de los hosts de Mininet para lanzar
# arp_spoof.py. Si existe el venv del proyecto lo usamos (así scapy
# se resuelve igual dentro y fuera); si no, caemos al python3 del PATH.
PYTHON_BIN = VENV_PYTHON if os.path.exists(VENV_PYTHON) else "python3"

# Igual para ryu-manager: si hay venv, usamos su binario explícito
# (evita depender de que sudo herede el PATH del venv activado).
RYU_MANAGER_BIN = VENV_RYU_MANAGER if os.path.exists(VENV_RYU_MANAGER) else "ryu-manager"

# --------------------------------------------------------------- #
# Ficheros compartidos / logs / dataset
# --------------------------------------------------------------- #
# Todo dentro del propio proyecto (NO en /tmp): así el CSV, el log del
# controlador y el log de generación son siempre visibles con tu
# usuario normal, incluso si ejecutas todo con sudo (algunos sistemas
# aíslan /tmp por sesión, lo que hace que un fichero escrito por root
# en /tmp "desaparezca" al mirarlo luego sin sudo).
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime")  # estado efímero compartido (label actual)

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

POLL_INTERVAL = 2          # segundos entre rondas de OFPFlowStatsRequest
FLOW_IDLE_TIMEOUT = 3
FLOW_HARD_TIMEOUT = 10

# --------------------------------------------------------------- #
# Topología Mininet
# --------------------------------------------------------------- #
TOPO_DEPTH = 2
TOPO_FANOUT = 4

# Ancho de banda (Mbps) de cada enlace virtual. Sin límite, iperf TCP
# satura el enlace software de Mininet a velocidades poco realistas
# (varios Gbps), lo que infla artificialmente pps/bps del tráfico
# "normal" y lo acerca demasiado al de un DDoS en el espacio de
# características. Con un límite tipo LAN, el tráfico normal se
# mantiene en rangos realistas y más separables de los ataques.
LINK_BANDWIDTH_MBPS = 10

# --------------------------------------------------------------- #
# Generación de tráfico
# --------------------------------------------------------------- #
# TARGET_ROWS es el criterio de parada REAL: en cuanto el CSV alcanza
# este nº de filas, se corta la generación aunque no haya pasado
# TOTAL_DURATION. Ponlo a None para desactivarlo y depender solo de
# TOTAL_DURATION.
TARGET_ROWS = 30000

# TOTAL_DURATION actúa como techo de seguridad (por si el tráfico
# generase muy pocos flujos y TARGET_ROWS tardase demasiado en
# alcanzarse). Con TARGET_ROWS activo normalmente se corta mucho antes.
TOTAL_DURATION = 4500
MIN_PHASE_DURATION = 10
MAX_PHASE_DURATION = 25

# Límite de filas que puede aportar UNA SOLA fase. Si una fase (p.ej.
# un DDoS o un spoofing con muchos flujos activos) se dispara y
# empieza a generar filas muy por encima de lo normal, se corta antes
# de agotar su duración -así ninguna fase puede acaparar el dataset y
# TARGET_ROWS se reparte entre muchas más fases distintas, dando más
# variedad-. Ponlo a None para desactivarlo.
MAX_ROWS_PER_PHASE = 1500

# Pausa de "asentamiento" al final de cada fase, ANTES de pasar a la
# siguiente (que es cuando se cambia la etiqueta). Da tiempo a que
# procesos recién matados (pkill) y paquetes ya en vuelo terminen de
# generar tráfico mientras la etiqueta todavía es la de la fase que
# acaba de terminar -que es lo correcto, ese tráfico es realmente
# suyo- en vez de que se cuelen ya bajo la etiqueta de la fase nueva.
PHASE_SETTLE_SECONDS = 1.5

# Margen de espera al arrancar la generación (antes de la primera fase),
# para que los flujos residuales del pingAll() inicial expiren solos
# (FLOW_IDLE_TIMEOUT) además de que el controlador los vacíe de forma
# reactiva al detectar el primer cambio de etiqueta -doble red de
# seguridad frente a que la primera fase herede ruido del arranque-.
STARTUP_SETTLE_SECONDS = FLOW_IDLE_TIMEOUT + 2

# Si es True, al arrancar el controlador se limpia cualquier
# data/dataset_sdn.csv previo y se empieza uno nuevo en limpio.
RESET_DATASET_ON_START = True

# Qué hacer con el CSV anterior al resetear: True lo archiva con
# timestamp (dataset_sdn_20260824_153000.csv); False lo borra sin más,
# para tener siempre un único data/dataset_sdn.csv.
ARCHIVE_PREVIOUS_DATASET = False

# Si es False, las filas del pingAll() inicial (etiqueta "warmup") ni
# siquiera se escriben en el CSV. Por defecto True (se generan, con su
# propia etiqueta) para que decidas tú en el preprocesado si las
# incluyes o las filtras -es reversible y queda documentado qué se
# excluyó y por qué-, en vez de perderlas de forma irreversible aquí.
WRITE_WARMUP_ROWS = True
