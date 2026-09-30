"""
defense/traffic.py
------------------
Tráfico de la fase 3. No tiene generadores propios: llama a las mismas
funciones de mininet_lab/traffic_generator.py que generaron el dataset,
para que el tráfico que el modelo ve en vivo sea idéntico al del
entrenamiento.

Solo ajusta lo que distingue la fase 3 de la generación del dataset:
desactiva el tope de filas por fase (ENFORCE_ROW_CAP), usa su propio log
y excluye el flood del DDoS según config.DEFENSE_DDOS_ALLOW_FLOOD.

Cada generador devuelve los actores de la prueba (atacantes, víctimas,
identidad suplantada), que set_label() también escribe en LABEL_FILE para
que el controlador de defensa etiquete cada flujo con el mismo criterio
que el entrenamiento.
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
