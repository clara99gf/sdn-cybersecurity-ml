"""
defense/traffic.py
------------------
Generadores de tráfico para la fase de detección y mitigación.

NO tiene generadores propios: llama a las MISMAS funciones que generaron
el dataset (mininet_lab/traffic_generator.py). Antes existía aquí una
copia "equivalente" de cada ataque, pero en la práctica había divergido
(otra duración de los nmap, pings e iperf distintos, ddos sin warmup ARP,
spoofing lanzado con un Python sin scapy...). Cada diferencia cambia las
features que ve el modelo en vivo respecto a las que vio al entrenar
(training-serving skew). Reutilizando el mismo código, esa fuente de
error desaparece por construcción.

Qué se ajusta para la fase 3 (sin tocar la generación del dataset):
  - ENFORCE_ROW_CAP = False: el tope de filas por fase solo tiene sentido
    mientras se genera el CSV del dataset.
  - LOG_FILE propio (logs/defense_traffic.log), para no mezclar la salida
    de las herramientas con el log de la generación del dataset.
  - DDoS con o sin la intensidad "--flood" según
    config.DEFENSE_DDOS_ALLOW_FLOOD (por defecto, sin: con el modelo
    clasificando en vivo, el flood total satura la CPU y cuelga Mininet).

Cada generador devuelve los ACTORES de la prueba: las funciones de
traffic_generator ya los devuelven (las mismas IPs que pasan a
set_label(): atacante(s), víctima(s) e identidad suplantada). Además, set_label() escribe LABEL_FILE igual que
en el dataset, y el controlador de defensa lo lee para calcular la
etiqueta REAL de cada flujo con el mismo criterio que el entrenamiento.
"""
import os
import sys

import config

# traffic_generator vive en mininet_lab/ y se importa como módulo suelto
# (igual que hace run_01_dataset.py con topology).
if config.MININET_LAB_DIR not in sys.path:
    sys.path.insert(0, config.MININET_LAB_DIR)
import traffic_generator as tg  # noqa: E402

tg.ENFORCE_ROW_CAP = False
tg.LOG_FILE = os.path.join(config.LOGS_DIR, "defense_traffic.log")

def reset_log():
    """Empieza el log de tráfico de la fase 3 en limpio."""
    open(tg.LOG_FILE, "w").close()


def kill_all_attack_procs(net=None):
    """Mata cualquier herramienta de tráfico que siga viva (en Mininet los
    hosts comparten espacio de procesos, así que basta con un pkill)."""
    tg._kill_all_attack_tools()


def _run(fn, net, duration, **kwargs):
    return list(fn(net, duration, **kwargs) or [])


def normal_traffic(net, duration):
    return _run(tg.normal_traffic, net, duration)


def scanning_traffic(net, duration):
    return _run(tg.scanning_traffic, net, duration)


def ddos_traffic(net, duration):
    return _run(tg.ddos_traffic, net, duration, allow_flood=config.DEFENSE_DDOS_ALLOW_FLOOD)


def spoofing_traffic(net, duration):
    return _run(tg.spoofing_traffic, net, duration)


GENERATORS = {
    "normal": normal_traffic,
    "scanning": scanning_traffic,
    "ddos": ddos_traffic,
    "spoofing": spoofing_traffic,
}
