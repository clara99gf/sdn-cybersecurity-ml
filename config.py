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
# Ficheros compartidos / logs
# --------------------------------------------------------------- #
LABEL_FILE = "/tmp/current_label.txt"
CSV_FILE = "/tmp/dataset_sdn.csv"
RYU_LOG_FILE = "/tmp/ryu_controller.log"
TRAFFIC_LOG_FILE = "/tmp/traffic_generator.log"

# --------------------------------------------------------------- #
# Controlador Ryu / OpenFlow
# --------------------------------------------------------------- #
RYU_CONTROLLER_IP = "127.0.0.1"
RYU_CONTROLLER_PORT = 6653

POLL_INTERVAL = 2          # segundos entre rondas de OFPFlowStatsRequest
FLOW_IDLE_TIMEOUT = 5
FLOW_HARD_TIMEOUT = 15

# --------------------------------------------------------------- #
# Topología Mininet
# --------------------------------------------------------------- #
TOPO_DEPTH = 2
TOPO_FANOUT = 4

# --------------------------------------------------------------- #
# Generación de tráfico
# --------------------------------------------------------------- #
TOTAL_DURATION = 7200      # segundos totales de simulación (ajusta para las ~12k filas)
MIN_PHASE_DURATION = 30
MAX_PHASE_DURATION = 90
