#!/usr/bin/env python3
"""
run_01_dataset.py
-----------------
Orquestador de la fase 1: genera el dataset con un solo comando.
 
Arranca el controlador Ryu (controller/sdn_monitor.py) en segundo plano,
espera a que escuche, levanta la topología Mininet y lanza la generación
de tráfico. Al terminar, o si se interrumpe con Ctrl+C, detiene el
controlador, limpia el estado de Mininet y devuelve al usuario la
propiedad de los ficheros creados con sudo.
 
    sudo venv/bin/python3 run_01_dataset.py    (ver EJECUCION.md)
"""
import os
import shutil
import socket
import subprocess
import sys
import time

import config

# Necesario para "import topology" (más abajo): setup.py registra el
# paquete como mininet_lab.topology, no como "topology" a secas.
sys.path.insert(0, config.MININET_LAB_DIR)


def wait_for_port(host, port, timeout=30):
    """Sondea el puerto con conexiones TCP hasta que acepta (True) o se
    agota el timeout (False). Sirve para esperar a que Ryu esté listo."""
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def resolve_ryu_manager():
    """Devuelve la ruta de 'ryu-manager', priorizando el del venv y
    recurriendo al del PATH si no está."""
    if os.path.exists(config.VENV_RYU_MANAGER):
        return config.VENV_RYU_MANAGER
    return shutil.which("ryu-manager")


def print_log_tail(path, n=25):
    """Muestra por consola las últimas 'n' líneas del archivo de log especificado."""
    try:
        with open(path) as f:
            lines = f.readlines()
        content = "".join(lines[-n:]).strip()
        print(content if content else "(el log está vacío)")
    except FileNotFoundError:
        print(f"(no se encontró {path})")


def main():
    """Arranca el controlador, lanza la topología y limpia todo al
    terminar. Requiere sudo (Mininet lo necesita)."""
    if os.geteuid() != 0:
        print("Este script debe ejecutarse con sudo (Mininet lo requiere). "
              "Consulta EJECUCION.md.")
        sys.exit(1)

    ryu_bin = resolve_ryu_manager()
    if ryu_bin is None:
        print(f"No se encontró 'ryu-manager' ni en el venv "
              f"({config.VENV_RYU_MANAGER}) ni en el PATH.\n"
              "Ejecuta ./setup.sh, que instala Ryu en el venv y aplica el "
              "parche que necesita para arrancar. Ryu solo es compatible con "
              "Python 3.8-3.10.")
        sys.exit(1)

    print(f"*** Arrancando el controlador Ryu ({ryu_bin})...")
    log_fp = open(config.RYU_LOG_FILE, "w")
    ryu_proc = subprocess.Popen(
        [ryu_bin, config.CONTROLLER_SCRIPT],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )

    try:
        print(f"*** Esperando a que Ryu escuche en "
              f"{config.RYU_CONTROLLER_IP}:{config.RYU_CONTROLLER_PORT}...")
        if not wait_for_port(config.RYU_CONTROLLER_IP, config.RYU_CONTROLLER_PORT):
            log_fp.flush()
            print("El controlador Ryu no arrancó a tiempo.\n"
                  f"--- Últimas líneas de {config.RYU_LOG_FILE} ---")
            print_log_tail(config.RYU_LOG_FILE)
            sys.exit(1)
        print("*** Controlador listo. Lanzando la topología Mininet...\n")

        import topology
        topology.main()

    except KeyboardInterrupt:
        print("\n*** Interrumpido por el usuario.")
    finally:
        print("*** Deteniendo el controlador Ryu...")
        ryu_proc.terminate()
        try:
            ryu_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            ryu_proc.kill()
        log_fp.close()

        print("*** Limpiando estado residual de Mininet (mn -c, por si algo "
              "se saltó la limpieza de topology.py)...")
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        # Devuelve al usuario los ficheros creados con sudo, para que la
        # fase 2 (sin sudo) pueda escribir en ellos.
        config.restore_ownership()

        print(f"\n*** Fin.")
        print(f"    Dataset:               {config.CSV_FILE}")
        print(f"    Log del controlador:   {config.RYU_LOG_FILE}")
        print(f"    Log de generación:     {config.TRAFFIC_LOG_FILE}")


if __name__ == "__main__":
    main()
