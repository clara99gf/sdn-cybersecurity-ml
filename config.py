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
# Parejas IP/MAC reales de cada host, escritas por topology.py justo
# tras levantar la red (con host.IP()/host.MAC(), la propia API de
# Mininet -no una convención adivinada-) y leídas por el controlador al
# arrancar, para "sembrar" ip_to_mac con la verdad de referencia desde
# el principio -en vez de tener que "aprenderla" del primer paquete que
# llegue, lo cual falla si ese primer paquete es ya un ataque de
# spoofing de ARP-. Formato: una línea por host, "ip,mac".
HOST_IDENTITY_FILE = os.path.join(RUNTIME_DIR, "host_identities.csv")
CSV_FILE = os.path.join(DATA_DIR, "dataset_sdn.csv")
RYU_LOG_FILE = os.path.join(LOGS_DIR, "ryu_controller.log")
TRAFFIC_LOG_FILE = os.path.join(LOGS_DIR, "traffic_generator.log")

# --------------------------------------------------------------- #
# Controlador Ryu / OpenFlow
# --------------------------------------------------------------- #
RYU_CONTROLLER_IP = "127.0.0.1"
RYU_CONTROLLER_PORT = 6653

# Intervalo entre solicitudes de estadísticas de flujo al switch (segundos).
# Bajado de 2s a 1s a propósito: el sondeo periódico solo "ve" un flujo
# si le pregunta al switch mientras ese flujo sigue instalado. Los
# flujos CORTOS (una sonda de escaneo suelta, un paquete de spoofing)
# viven poco, así que con sondeos cada 2s se perdían a menudo -y son
# justo la firma que distingue cada ataque, mientras que el tráfico de
# fondo (ARP/ICMP, más duradero) sí se capturaba siempre, diluyendo la
# señal-. A 1s, cada flujo tiene el doble de oportunidades de ser
# capturado. Coste: más carga en el controlador y más filas por fase.
POLL_INTERVAL = 1
# Tiempo de inactividad tras el cual se elimina un flujo (segundos).
# Subido de 3s a 5s por el mismo motivo, atacando el problema desde el
# otro lado: si el flujo sobrevive más tiempo en el switch, hay más
# margen para que algún sondeo lo capture antes de que desaparezca.
FLOW_IDLE_TIMEOUT = 5
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
# NOTA: en modo prueba (30000) para validar el efecto de POLL_INTERVAL=1
# y las sondas ACK más largas antes de la tirada final. Con el sondeo al
# doble de frecuencia, 30000 filas tardan ~34 min (antes ~68).
# Número objetivo de filas del dataset.
# 300.000 (subido desde 150.000) tras comprobar con la curva de
# aprendizaje que MÁS FASES siguen mejorando el modelo: pasar de 230 a
# 345 fases dio +0.035 de F1, sin señal de aplanamiento -antes de
# corregir el etiquetado por flujo la curva sí se aplanaba, por eso
# entonces no compensaba-. Con ~325 filas/fase de media, 300.000 filas
# dan ~920 fases (el doble que ahora).
TARGET_ROWS = 300000
# TARGET_ROWS = 30000  # <- tamaño para tiradas de prueba rápidas

# Duración máxima de la generación (segundos). Es un techo de SEGURIDAD
# para que no se quede corriendo indefinidamente si algo va mal, NO la
# duración esperada -TARGET_ROWS es el criterio de parada real-.
# Recalculado con el ritmo REAL medido en la última tirada: 150.029
# filas en 8.771s = 17,1 filas/s. Para 300.000 filas eso son ~4,9h;
# este techo (6,6h) deja un 35% de margen.
TOTAL_DURATION = 23700
# Para tiradas de prueba de 30.000 filas: ~3000s es suficiente.
# TOTAL_DURATION = 3000

# Duración mínima y máxima de cada fase de tráfico (segundos)
MIN_PHASE_DURATION = 10         
MAX_PHASE_DURATION = 25

# Límite de filas que puede aportar UNA SOLA fase.
# 500 (bajado desde 800): con POLL_INTERVAL=1s cada fase genera muchas
# más filas, y con el techo más alto una tirada de 150.000 se agotaba en
# solo ~400 fases -pocas para GroupKFold, que gana fiabilidad cuantos
# más grupos independientes tenga-. Con 500 se esperan ~600-700 fases
# para el mismo volumen, sin perder la mejora de captura del sondeo
# rápido.
MAX_ROWS_PER_PHASE = 500

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

# Indica si las filas generadas durante la fase inicial de calentamiento
# se almacenan. Se mantiene en True (preprocessing.py las descarta
# igualmente al preparar el dataset, y tenerlas en el CSV crudo permite
# revisar el arranque si algo va mal). NOTA: con POLL_INTERVAL=1s el
# warmup genera bastantes más filas que antes (~7000 de 30000 en una
# tirada de prueba, frente a ~1800 con POLL=2s) -no afecta al modelo,
# pero infla el CSV crudo; si molesta, ponerlo en False-.
WRITE_WARMUP_ROWS = True

# Interruptor de depuración: registra en logs/ryu_controller.log cada
# paquete TCP visto por packet_in (con sus flags) y cualquier paquete IP
# no reconocido como TCP/UDP -útil para investigar por qué un tipo de
# tráfico concreto no se está capturando bien. Poner a False (por
# defecto) salvo que se esté depurando algo así -genera mucho log si se
# deja activo en una tirada grande-.
DEBUG_TCP_FLAGS = False

# --------------------------------------------------------------- #
# Preprocesado / entrenamiento / evaluación (ml/)
# --------------------------------------------------------------- #
# Se añaden aquí, sin tocar nada de lo de arriba, para no arriesgar la
# parte de generación del dataset (ya validada en muchas rondas).
DATA_PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")
TABLES_DIR = os.path.join(RESULTS_DIR, "tables")

for _d in (DATA_PROCESSED_DIR, MODELS_DIR, FIGURES_DIR, TABLES_DIR):
    os.makedirs(_d, exist_ok=True)

RANDOM_STATE = 42
TEST_SIZE = 0.2

# Nº de características a conservar tras la selección por importancia
# (Random Forest), dentro de cada fold.
#
# PENDIENTE DE REVALIDAR: el valor 15 se fijó hace tiempo, cuando el
# dataset tenía más columnas y la evaluación aún usaba split aleatorio
# (con fuga de información). Ahora solo hay 21 características, así que
# el recorte descarta 6 -y una medición sin recorte dio un F1 algo más
# alto-. Merece la pena comparar 15 frente a 21 ejecutando
# `ml/evaluate.py` con cada valor (~2,5 min cada uno) y quedarse con el
# mejor, en vez de arrastrar un número heredado.
N_FEATURES = 15

TARGET_COLUMN = "label"

# Identificadores "rígidos": permiten que el modelo memorice hosts o
# instantes concretos del laboratorio (una IP/MAC siempre jugando el
# mismo papel, el timestamp de una ejecución concreta) en vez de
# aprender patrones de tráfico generalizables. Se excluyen siempre.
# Incluye también las MACs y "dpid" (identifican host/switch del
# laboratorio, mismo problema que una IP) además de IP y timestamp.
ID_COLUMNS = [
    "timestamp",
    "ip_src", "ip_dst",
    "eth_src", "eth_dst",
    "arp_spa", "arp_tpa", "arp_sha",
    "dpid",
    # phase_id: identificador de fase para GroupKFold. NUNCA debe entrar
    # como característica -sería una fuga de información masiva (el
    # modelo aprendería "la fase 37 es scanning" en vez de a reconocer
    # tráfico)-. Se usa solo para agrupar en la validación cruzada.
    "phase_id",
]

# Constantes de configuración (no del tráfico): mismo valor en TODAS
# las filas del dataset (vienen fijadas en config.py del generador,
# no varían por flujo). Aportan cero información -en la práctica ya
# quedaban fuera de las N_FEATURES seleccionadas por tener importancia
# ~0, pero se excluyen aquí de forma explícita en vez de confiar en
# que la selección estadística siempre las deje fuera-.
CONSTANT_COLUMNS = ["idle_timeout", "hard_timeout"]

# Categóricas de baja cardinalidad -> codificación numérica
# (LabelEncoder) en vez de tratarlas como magnitud continua.
# tcp_flags: combinaciones concretas de bits (SYN, SYN+ACK, ACK solo,
# etc.) son categorías cualitativamente distintas, no una escala -por
# eso va aquí y no como número continuo, igual que ip_proto/eth_type-.
CATEGORICAL_COLUMNS = ["eth_type", "ip_proto", "arp_opcode", "tcp_flags"]

# Columnas con NaN estructural (no aplica a ese protocolo, no es un
# dato perdido) -> se rellenan con 0, no se elimina la fila.
STRUCTURAL_NA_COLUMNS = [
    "ip_proto", "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port", "arp_opcode",
    "tcp_flags",  # "" si el flujo no es TCP (ARP/ICMP/UDP), mismo criterio
    "ip_mac_consistent",  # "" solo si el flujo ya existía antes de
                           # arrancar el controlador (caso raro) -no es
                           # ideal que se rellene con 0 (mismo valor que
                           # "inconsistente"), pero es un caso marginal
                           # y mantiene el mismo criterio que el resto
                           # de columnas "no aplica" del proyecto.
    "arp_unsolicited_reply",  # "" en todo lo que no sea una respuesta
                               # ARP (la inmensa mayoría de filas)
]

# Columnas de tasas: si aquí aparece un infinito o NaN real (no
# estructural), es indeterminación aritmética -> esas filas SÍ se
# eliminan (son pocas, y no tiene sentido imputarlas).
RATE_COLUMNS = ["packet_count_per_second", "byte_count_per_second", "avg_packet_size"]

