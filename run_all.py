#!/usr/bin/env python3
"""
run_all.py
----------
Lanza TODO el proceso de generación del dataset con un único comando:
  1) Arranca el controlador Ryu (controller/sdn_monitor.py) en segundo plano.
  2) Espera a que esté escuchando en RYU_CONTROLLER_PORT.
  3) Levanta la topología Mininet y genera el tráfico.
  4) Al terminar (o si se interrumpe con Ctrl+C), detiene el controlador
     y limpia el estado residual de Mininet (mn -c).

Debe ejecutarse como root, porque Mininet lo requiere. Los comandos
exactos (con o sin entorno virtual) están en EJECUCION.md.
"""
import os
import socket
import subprocess
import sys
import time

import config

sys.path.insert(0, config.MININET_LAB_DIR)


def wait_for_port(host, port, timeout=30):
    start = time.time()
    while time.time() - start < timeout:
        try:
            with socket.create_connection((host, port), timeout=1):
                return True
        except OSError:
            time.sleep(0.5)
    return False


def main():
    if os.geteuid() != 0:
        print("Este script debe ejecutarse con sudo (Mininet lo requiere). "
              "Consulta EJECUCION.md.")
        sys.exit(1)

    print(f"*** Arrancando el controlador Ryu ({config.RYU_MANAGER_BIN})...")
    log_fp = open(config.RYU_LOG_FILE, "w")
    ryu_proc = subprocess.Popen(
        [config.RYU_MANAGER_BIN, config.CONTROLLER_SCRIPT],
        stdout=log_fp, stderr=subprocess.STDOUT,
    )

    try:
        print(f"*** Esperando a que Ryu escuche en "
              f"{config.RYU_CONTROLLER_IP}:{config.RYU_CONTROLLER_PORT}...")
        if not wait_for_port(config.RYU_CONTROLLER_IP, config.RYU_CONTROLLER_PORT):
            print("El controlador Ryu no arrancó a tiempo. "
                  f"Revisa el log: {config.RYU_LOG_FILE}")
            sys.exit(1)
        print("*** Controlador listo. Lanzando la topología Mininet...\n")

        import topology  # mininet_lab/topology.py (import diferido: necesita sys.path ya listo)
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
