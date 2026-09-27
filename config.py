#!/usr/bin/env python3
"""
config.py
---------
Configuración centralizada del proyecto: rutas y parámetros de las tres
fases. Los módulos de todas ellas importan este fichero, de modo que
cada valor está definido en un único sitio.
"""
import os

# Ignora los paquetes instalados en ~/.local para que no interfieran con
# los del entorno virtual, sobre todo al ejecutar con sudo.
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

# Se prefiere el entorno virtual, que tiene scapy y ryu; si no existe,
# se recurre al del sistema.
PYTHON_BIN = VENV_PYTHON if os.path.exists(VENV_PYTHON) else "python3"
RYU_MANAGER_BIN = VENV_RYU_MANAGER if os.path.exists(VENV_RYU_MANAGER) else "ryu-manager"

# --------------------------------------------------------------- #
# Directorios y ficheros generados
# --------------------------------------------------------------- #
DATA_DIR = os.path.join(PROJECT_ROOT, "data")
LOGS_DIR = os.path.join(PROJECT_ROOT, "logs")
RUNTIME_DIR = os.path.join(PROJECT_ROOT, "runtime") 

for _d in (DATA_DIR, LOGS_DIR, RUNTIME_DIR):
    os.makedirs(_d, exist_ok=True)

# Coordinación entre el generador de tráfico y el controlador, que son
# procesos independientes.
LABEL_FILE = os.path.join(RUNTIME_DIR, "current_label.txt")
FLUSH_REQUEST_FILE = os.path.join(RUNTIME_DIR, "flush_request.txt")

# Parejas IP/MAC reales de cada host ("ip,mac" por línea), escritas por
# topology.py y leídas por el controlador al arrancar. Dan la
# vinculación legítima desde el principio: aprenderla del tráfico
# fallaría si el primer paquete de un host ya fuera un ARP falsificado.
HOST_IDENTITY_FILE = os.path.join(RUNTIME_DIR, "host_identities.csv")

CSV_FILE = os.path.join(DATA_DIR, "dataset_sdn.csv")
RYU_LOG_FILE = os.path.join(LOGS_DIR, "ryu_controller.log")
TRAFFIC_LOG_FILE = os.path.join(LOGS_DIR, "traffic_generator.log")

# --------------------------------------------------------------- #
# Controlador Ryu / OpenFlow
# --------------------------------------------------------------- #
RYU_CONTROLLER_IP = "127.0.0.1"
RYU_CONTROLLER_PORT = 6653

# Intervalo entre solicitudes de estadísticas al switch (segundos). Un
# flujo solo se observa mientras está instalado, y los más cortos (una
# sonda de escaneo, un paquete de spoofing) son la firma de cada ataque:
# sondear cada segundo da más oportunidades de capturarlos.
POLL_INTERVAL = 1

# Tiempo sin tráfico tras el cual el switch elimina un flujo, y tiempo
# máximo de permanencia (segundos). Así un flujo corto sobrevive a
# varios sondeos sin que los largos acumulen contadores de minutos.
FLOW_IDLE_TIMEOUT = 5
FLOW_HARD_TIMEOUT = 10      

# --------------------------------------------------------------- #
# Topología Mininet
# --------------------------------------------------------------- #
TOPO_DEPTH = 2              # Profundidad del árbol
TOPO_FANOUT = 4             # Hijos por nodo; con depth=2 da 5 switches y 16 hosts
LINK_BANDWIDTH_MBPS = 10    # Ancho de banda de cada enlace virtual

# --------------------------------------------------------------- #
# Fase 1: generación del dataset
# (run_01_dataset.py, mininet_lab/, controller/sdn_monitor.py)
# --------------------------------------------------------------- #
# Criterio de parada de la generación. A unas 300 filas por fase, dan
# alrededor de 900 fases-
TARGET_ROWS = 300000

# Techo de seguridad (segundos) por si no se alcanzan las TARGET_ROWS.
# No es la duración esperada, que ronda las cuatro horas.
TOTAL_DURATION = 23700

# Duración de cada fase de tráfico (segundos), sorteada en este rango.
MIN_PHASE_DURATION = 10         
MAX_PHASE_DURATION = 25

# Tope aproximado de filas por fase, para que ninguna domine el
# conjunto. Se comprueba entre acciones, así que no interrumpe una
# herramienta ya lanzada (nmap, hping3, iperf): 242 de las 909 fases superan las 500.
MAX_ROWS_PER_PHASE = 500

# Pausas entre fases y antes de la primera, para que los flujos de la
# anterior expiren y no se mezclen con la siguiente.
PHASE_SETTLE_SECONDS = 1.5
STARTUP_SETTLE_SECONDS = FLOW_IDLE_TIMEOUT + 2

# Cada ejecución empieza un CSV nuevo; el segundo decide si el anterior
# se conserva con marca de tiempo o se descarta.
RESET_DATASET_ON_START = True
ARCHIVE_PREVIOUS_DATASET = False

# Escribe las filas del calentamiento con la etiqueta "warmup". El
# preprocesado las descarta, pero permiten revisar el arranque.
WRITE_WARMUP_ROWS = True

# Registra cada paquete TCP con sus flags. Solo para depuración: en una
# tirada larga genera muchísimo log.
DEBUG_TCP_FLAGS = False

# --------------------------------------------------------------- #
# Fase 2: preprocesado, entrenamiento y evaluación (ml/)
# --------------------------------------------------------------- #
DATA_PROCESSED_DIR = os.path.join(DATA_DIR, "processed")
MODELS_DIR = os.path.join(PROJECT_ROOT, "models")
RESULTS_DIR = os.path.join(PROJECT_ROOT, "results")
FIGURES_DIR = os.path.join(RESULTS_DIR, "figures")
TABLES_DIR = os.path.join(RESULTS_DIR, "tables")

for _d in (DATA_PROCESSED_DIR, MODELS_DIR, FIGURES_DIR, TABLES_DIR):
    os.makedirs(_d, exist_ok=True)

# Semilla fija para garantizar la reproducibilidad de la fase 2
# cuando se ejecuta de nuevo bajo las mismas condiciones.
RANDOM_STATE = 42
TEST_SIZE = 0.2

# Nº de características que se conservan tras la selección por
# importancia (Random Forest), dentro de cada partición. Se eligen 15:
# las 7 descartadas suman un 6.1% de la importancia y su
# ausencia no cambia el F1.
N_FEATURES = 15

# Ventana temporal (segundos) de las 4 características de "patrón entre
# flujos". Es del orden de FLOW_IDLE_TIMEOUT, así que abarca la vida
# típica de un flujo, y queda por debajo de MIN_PHASE_DURATION, así que
# nunca mezcla dos fases.
#
# La usan ml/preprocessing.py (modo lote) y controller/live_classifier.py
# (modo evento) y deben coincidir: si no, el modelo vería en detección
# una característica calculada de otra forma que al entrenar.
WINDOW_SECONDS = 5

TARGET_COLUMN = "label"

# Identificadores del laboratorio: permitirían memorizar qué host o qué
# instante participó en cada ataque, en vez de aprender patrones de
# tráfico. Se excluyen siempre de las características.
ID_COLUMNS = [
    "timestamp",
    "ip_src", "ip_dst",
    "eth_src", "eth_dst",
    "arp_spa", "arp_tpa", "arp_sha",
    "dpid",
    # Solo para agrupar en la validación cruzada. Como característica
    # sería una fuga: el modelo aprendería qué fase es cada ataque.
    "phase_id",
]

# Mismo valor en todas las filas, porque proceden de este fichero y no
# del tráfico. Se excluyen explícitamente, sin confiar en que la
# selección por importancia las descarte.
CONSTANT_COLUMNS = ["idle_timeout", "hard_timeout"]

# Columnas cuyo número es un código, no una cantidad: el protocolo 17
# (UDP) no es "más" que el 6 (TCP), solo distinto. Se codifican con
# LabelEncoder para que el modelo no las interprete como magnitudes.
CATEGORICAL_COLUMNS = ["eth_type", "ip_proto", "arp_opcode", "tcp_flags"]

# Columnas con NaN estructural (no aplica a ese protocolo, no es un
# dato perdido): se rellenan con 0, no se elimina la fila.
STRUCTURAL_NA_COLUMNS = [
    "ip_proto", "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port", "arp_opcode",
    "tcp_flags",              # vacío si el flujo no es TCP
    "ip_mac_consistent",      # vacío solo si el flujo existía antes de
                              # arrancar el controlador, caso marginal
    "arp_unsolicited_reply",  # vacío en todo lo que no sea respuesta ARP
]

# En las tasas, un infinito o un NaN es una indeterminación aritmética,
# no un "no aplica": esas filas sí se eliminan.
RATE_COLUMNS = ["packet_count_per_second", "byte_count_per_second", "avg_packet_size"]

# --------------------------------------------------------------- #
# Fase 3: detección y mitigación en vivo
# (run_03_defense.py, controller/sdn_defense.py, defense/)
# --------------------------------------------------------------- #
# Duración de cada prueba (segundos) y excepciones por tipo. Las cuatro
# duran lo mismo para que sus resultados sean comparables.
DEFENSE_PHASE_DURATION = 30
DEFENSE_PHASE_DURATION_BY_KIND = {}

# Intensidad "--flood" del DDoS, desactivada aquí. hping3 --flood envía
# sin límite de tasa, y Mininet ejecuta hosts, switches y controlador en
# la misma máquina: lo que se satura es el entorno de emulación, no el
# sistema de defensa. Las otras dos intensidades del dataset (~500 y
# ~1000 pps) sí se usan.
DEFENSE_DDOS_ALLOW_FLOOD = False

# Duración de cada regla DROP (segundos). Temporal a propósito: la red
# no queda bloqueada por reglas residuales y un ataque que continúa se
# vuelve a detectar y a bloquear.
DEFENSE_DROP_TIMEOUT = 20

# Nº de sondeos distintos, dentro de DEFENSE_CONFIRM_WINDOW_S segundos,
# en los que una conversación (MAC origen -> MAC destino) debe salir
# clasificada como ataque antes de bloquearla. Exigir varias
# confirmaciones evita que un error aislado del modelo corte tráfico
# legítimo; un ataque real es sostenido y se confirma igualmente en
# pocos segundos.
DEFENSE_MITIGATION_CONFIRMATIONS = 3
DEFENSE_CONFIRM_WINDOW_S = 5

# Margen tras activar una prueba durante el que el controlador descarta
# las estadísticas en tránsito, que describen flujos anteriores.
DEFENSE_ACTIVATION_GRACE_S = 2 * POLL_INTERVAL + 0.5

# Repeticiones de la batería completa. Cada una sortea atacantes,
# víctimas y variantes, y el resultado varía mucho entre ellas: las
# métricas se informan como media y desviación de las 10.
DEFENSE_BATTERY_RUNS = 10

def restore_ownership():
    """Devuelve la propiedad de los directorios de salida al usuario que
    invocó sudo.

    Las fases 1 y 3 necesitan root (Mininet), así que todo lo que crean
    pertenece a root. Luego la fase 2 y defense/plots.py, que se ejecutan
    SIN sudo, no pueden escribir ahí y fallan con PermissionError. Esto se
    llama al terminar esas fases para dejar el proyecto utilizable con el
    usuario normal. Sin sudo (o si algo falla) no hace nada."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if not uid or not gid:
        return
    import subprocess
    for d in (DATA_DIR, LOGS_DIR, RUNTIME_DIR, MODELS_DIR, RESULTS_DIR):
        try:
            subprocess.run(["chown", "-R", f"{uid}:{gid}", d],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        except Exception:
            pass
