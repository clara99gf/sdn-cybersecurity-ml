#!/usr/bin/env python3
"""
run_all.py
----------
Lanza TODO el proceso de generación del dataset con un único comando:
  1) Localiza y arranca el controlador Ryu (controller/sdn_monitor.py)
     en segundo plano.
  2) Espera a que esté escuchando en RYU_CONTROLLER_PORT.
  3) Levanta la topología Mininet y genera el tráfico.
  4) Al terminar (o si se interrumpe con Ctrl+C), detiene el controlador
     y limpia el estado residual de Mininet (mn -c).

Ejecución:
    sudo venv/bin/python3 run_all.py (Ver EJECUCION.md).
"""
import os
import shutil
import socket
import subprocess
import sys
import time

import config

# IMPRESCINDIBLE, no una redundancia: sin esto, "import topology" (más
# abajo) falla con ModuleNotFoundError. pip install -e . no lo sustituye:
# setup.py registra mininet_lab como paquete con prefijo
# (mininet_lab.topology), no como "topology" a secas.
sys.path.insert(0, config.MININET_LAB_DIR)


def wait_for_port(host, port, timeout=30):
    """
    Realiza sondeos periódicos mediante sockets TCP para comprobar si un puerto está abierto.

    Retorna True tan pronto como se acepta la conexión, o False si se agota el timeout.
    """
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def resolve_ryu_manager():
    """
    Localiza el ejecutable 'ryu-manager'.
    Prioriza el entorno virtual (venv) del proyecto y, si no lo encuentra, busca en el PATH global.
    """
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
    if os.geteuid() != 0:
        print("Este script debe ejecutarse con sudo (Mininet lo requiere). "
              "Consulta EJECUCION.md.")
        sys.exit(1)

    ryu_bin = resolve_ryu_manager()
    if ryu_bin is None:
        print(f"No se encontró 'ryu-manager' ni en el venv "
              f"({config.VENV_RYU_MANAGER}) ni en el PATH.\n"
              "Prueba:\n"
              "  ./venv/bin/pip install ryu\n"
              "y comprueba que aparece ./venv/bin/ryu-manager. Si tu versión "
              "de Python es muy reciente (3.11+), 'ryu' (poco mantenido) "
              "puede fallar al instalar por incompatibilidad con eventlet; "
              "la alternativa es usar un venv con Python 3.8/3.9, o el fork "
              "mantenido 'os-ken' (misma API).")
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

        print("*** Limpiando estado residual de Mininet (mn -c)...")
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

        print(f"\n*** Fin.")
        print(f"    Dataset:               {config.CSV_FILE}")
        print(f"    Log del controlador:   {config.RYU_LOG_FILE}")
        print(f"    Log de generación:     {config.TRAFFIC_LOG_FILE}")


if __name__ == "__main__":
    main()
