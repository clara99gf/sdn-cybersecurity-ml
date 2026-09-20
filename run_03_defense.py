#!/usr/bin/env python3
"""
run_03_defense.py
-----------------
Orquestador de la FASE DE DETECCIÓN Y MITIGACIÓN (tercera fase del TFG).

Menú interactivo en terminal que permite:
  - Lanzar tráfico de UN tipo (normal / ddos / scanning / spoofing) y ver
    cómo el controlador lo detecta y mitiga en vivo.
  - Lanzar la BATERÍA COMPLETA: los cuatro tipos en secuencia, con estado
    limpio entre cada uno, y generar todas las gráficas al final.
  - Generar las gráficas a partir de las métricas ya recogidas.
  - Salir limpiando el entorno (mn -c, matar Ryu).

Levanta por su cuenta el controlador de defensa (controller/sdn_defense.py)
y la topología Mininet, igual que run_01_dataset.py hace con la de
generación. Requiere sudo (Mininet).

Uso:
    sudo venv/bin/python3 run_03_defense.py
"""
import os
import signal
import subprocess
import sys
import time
from functools import partial

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import config

CONTROLLER = os.path.join("controller", "sdn_defense.py")
EVENTS_CSV = os.path.join(config.PROJECT_ROOT, "results", "metrics", "defense_events.csv")
# Archivo-interruptor que activa la detección/mitigación en el controlador
# (ver ACTIVE_FLAG en sdn_defense.py). Solo existe mientras corre una prueba.
ACTIVE_FLAG = os.path.join(config.RUNTIME_DIR, "defense_active.flag")
# Flag que el controlador crea cuando ha terminado de limpiar las reglas
# DROP al final de una prueba (ver CLEAN_FLAG en sdn_defense.py).
CLEAN_FLAG = os.path.join(config.RUNTIME_DIR, "defense_clean.flag")
POLL_INTERVAL = config.POLL_INTERVAL


def _clear_clean_flag():
    if os.path.exists(CLEAN_FLAG):
        try:
            os.remove(CLEAN_FLAG)
        except OSError:
            pass


def _wait_clean(timeout=15):
    """Espera a que el controlador confirme que ha limpiado las reglas
    DROP (crea CLEAN_FLAG). Evita hacer el pingAll de recuperación con
    reglas DROP aún activas."""
    t0 = time.time()
    while time.time() - t0 < timeout:
        if os.path.exists(CLEAN_FLAG):
            return True
        time.sleep(0.3)
    return False

# Duración por defecto de cada prueba de tráfico (segundos). 30s da
# tiempo a capturar suficientes flujos de cada tipo sin alargar en
# exceso.
PHASE_DURATION = 30

# Duraciones específicas por tipo cuando conviene apartarse del valor por
# defecto. El scanning necesita más tiempo: su firma es "muchos flujos
# activos acumulados" (flow_count_per_dpid alto), que en vivo tarda en
# consolidarse -un escaneo real es sostenido, así que darle más tiempo
# es más realista-. Este diccionario lo usan TANTO las pruebas
# individuales COMO la batería (ambas pasan por _run_single), así que
# ajustar aquí basta para los dos casos.
PHASE_DURATION_BY_KIND = {
    "scanning": 45,
}


def _set_active(active, kind=""):
    """Activa (crea) o desactiva (borra) el flag que le dice al
    controlador que clasifique y mitigue. El flag contiene el TIPO de
    prueba en marcha (normal/scanning/ddos/spoofing), que el controlador
    guarda en cada evento (columna traffic_phase) -así las gráficas y
    tablas separan por prueba aunque los tiempos se solapen-.
    Fuera de una prueba, el controlador no toca el tráfico."""
    if active:
        with open(ACTIVE_FLAG, "w") as f:
            f.write(kind)
    elif os.path.exists(ACTIVE_FLAG):
        os.remove(ACTIVE_FLAG)


# --------------------------------------------------------------------- #
# Arranque y parada del entorno
# --------------------------------------------------------------------- #
def _start_controller():
    ryu_cmd = _ryu_command()
    log_path = os.path.join(config.LOGS_DIR, "ryu_defense.log")
    print(f"*** Arrancando el controlador de defensa...")
    proc = subprocess.Popen(
        ryu_cmd + [CONTROLLER],
        stdout=open(log_path, "w"),
        stderr=subprocess.STDOUT,
        preexec_fn=os.setsid,
    )
    # Esperar a que Ryu escuche, comprobando ADEMÁS que el proceso sigue
    # vivo -si el controlador falla al importar (p.ej. un import roto),
    # muere en el acto y el puerto nunca abre; hay que avisar en vez de
    # seguir y dejar la red sin controlador (100% de pings caídos).
    listening = False
    for _ in range(30):
        if proc.poll() is not None:  # el proceso ha terminado
            break
        if _port_open(config.RYU_CONTROLLER_IP, config.RYU_CONTROLLER_PORT):
            listening = True
            break
        time.sleep(0.5)

    if not listening:
        print("\n*** ERROR: el controlador de defensa no llegó a escuchar en "
              f"{config.RYU_CONTROLLER_IP}:{config.RYU_CONTROLLER_PORT}.")
        print("*** Probablemente falló al arrancar. Últimas líneas de "
              f"{log_path}:\n")
        try:
            with open(log_path) as f:
                tail = f.readlines()[-15:]
            print("".join("    " + l for l in tail))
        except Exception:
            pass
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
        except Exception:
            pass
        subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(1)

    print("*** Controlador listo (escuchando).")
    return proc


def _ryu_command():
    """Comando para lanzar ryu-manager de forma que tenga acceso a las
    dependencias del venv (pandas, scikit-learn, joblib) -que el
    controlador de defensa necesita para cargar el modelo-.

    El problema: 'ryu-manager' suele estar instalado en el Python del
    SISTEMA (el venv se crea con --system-site-packages para ver Mininet),
    pero pandas/sklearn están en el venv. Si se lanza el ryu-manager del
    sistema a secas, no encuentra pandas y el controlador muere.

    Solución: ejecutar ryu-manager A TRAVÉS del Python del venv
    (venv/bin/python3 -m ryu.cmd.manager), que sí ve tanto las libs del
    venv como -por --system-site-packages- las del sistema (ryu).
    Si no hay venv, se cae al ryu-manager del sistema como último recurso.
    """
    venv_py = os.path.join(config.PROJECT_ROOT, "venv", "bin", "python3")
    if os.path.exists(venv_py):
        return [venv_py, "-m", "ryu.cmd.manager"]
    venv_ryu = os.path.join(config.PROJECT_ROOT, "venv", "bin", "ryu-manager")
    if os.path.exists(venv_ryu):
        return [venv_ryu]
    return ["ryu-manager"]


def _port_open(ip, port):
    import socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.settimeout(0.5)
        return s.connect_ex((ip, port)) == 0


def _build_net():
    from mininet.net import Mininet
    from mininet.node import RemoteController
    from mininet.topolib import TreeTopo
    from mininet.link import TCLink

    topo = TreeTopo(depth=config.TOPO_DEPTH, fanout=config.TOPO_FANOUT)
    link = partial(TCLink, bw=config.LINK_BANDWIDTH_MBPS)
    net = Mininet(topo=topo, link=link, controller=None, autoSetMacs=True)
    net.addController("c0", controller=RemoteController,
                      ip=config.RYU_CONTROLLER_IP, port=config.RYU_CONTROLLER_PORT)
    net.start()
    for node in net.hosts + net.switches:
        for intf in node.intfNames():
            if intf != "lo":
                node.cmd(f"ethtool -K {intf} tso off gso off gro off 2>/dev/null")
    # Esperar a que los 5 switches se conecten al controlador (igual que
    # topology.py en la fase 1: 5s). Con menos tiempo, algún switch aún no
    # tiene la regla table-miss instalada cuando empieza el tráfico, y sus
    # paquetes se caen -era la causa de los pings perdidos-.
    print("*** Esperando a que los switches se conecten al controlador...")
    time.sleep(5)
    # Un primer pingAll actúa de calentamiento: puebla las tablas ARP y
    # hace que el controlador aprenda todas las MAC. El segundo ya debería
    # salir limpio (sirve para confirmar que la red está bien antes de
    # empezar las pruebas).
    net.pingAll()
    print("*** Comprobación de conectividad:")
    net.pingAll()
    # Escribir las identidades reales IP/MAC de los hosts, igual que hace
    # topology.py en la fase 1: el controlador de defensa las carga para
    # sembrar la detección de spoofing con la verdad de referencia desde
    # el arranque. Se hace aquí para no depender de que la fase 1 se haya
    # ejecutado antes (Mininet asigna las mismas IPs/MACs, pero el archivo
    # podría no existir en una instalación limpia).
    with open(config.HOST_IDENTITY_FILE, "w") as f:
        for host in net.hosts:
            f.write(f"{host.IP()},{host.MAC()}\n")
    return net


def _cleanup(controller_proc=None, net=None):
    print("\n*** Limpiando entorno...")
    _set_active(False)  # quitar el flag de detección si quedó activo
    if net is not None:
        try:
            net.stop()
        except Exception:
            pass
    if controller_proc is not None:
        try:
            os.killpg(os.getpgid(controller_proc.pid), signal.SIGTERM)
        except Exception:
            pass
    subprocess.run(["pkill", "-f", "sdn_defense.py"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    print("*** Entorno limpio (mn -c ejecutado).")


# --------------------------------------------------------------------- #
# Pruebas de tráfico
# --------------------------------------------------------------------- #
def _run_single(net, kind, duration=None, reset=True, plot=True, summary=True):
    from defense import traffic, plots
    if reset:
        _reset_all(silent=True)   # borra métricas Y gráficas/tablas anteriores
    # Duración: la específica del tipo si la hay (ver
    # PHASE_DURATION_BY_KIND), o la general. Se aplica igual en pruebas
    # individuales y en la batería (ambas pasan por aquí).
    if duration is None:
        duration = PHASE_DURATION_BY_KIND.get(kind, PHASE_DURATION)
    print(f"\n*** Generando tráfico '{kind}' durante {duration}s...", flush=True)
    print("    (el controlador clasifica y mitiga en vivo; métricas -> "
          "results/metrics/defense_events.csv)", flush=True)
    _set_active(True, kind)   # activar detección+mitigación SOLO durante la prueba
    t0 = time.time()
    attackers = []
    try:
        attackers = traffic.GENERATORS[kind](net, duration) or []
    finally:
        # Borrar el flag de "limpieza hecha" y desactivar la prueba. El
        # controlador, al ver el flag desactivado, limpia las reglas DROP
        # y crea CLEAN_FLAG cuando termina.
        _clear_clean_flag()
        _set_active(False)
        # Matar CUALQUIER proceso de ataque en TODOS los hosts.
        for h in net.hosts:
            h.cmd("pkill -9 -f nmap 2>/dev/null; "
                  "pkill -9 -f hping3 2>/dev/null; "
                  "pkill -9 -f arp_spoof 2>/dev/null; "
                  "pkill -9 -f iperf 2>/dev/null")
        # Dar un margen breve a que el controlador limpie las reglas (ya
        # no se satura, porque la mitigación es por IP: pocos mensajes).
        # No es crítico esperar la confirmación: la limpieza se hace en el
        # controlador en su siguiente sondeo de todas formas.
        _wait_clean(timeout=4)
        # Ping LIGERO de recuperación (2 hosts, no los 240 pares): fuerza
        # que los switches reaprendan y confirma que la red responde.
        # NO se usa pingAll aquí: si la red quedara bloqueada, 240 pings
        # con timeout acumulan MINUTOS de cuelgue (llegó a tardar 536s).
        # Con 2 hosts y timeout corto, el peor caso son 2 segundos.
        try:
            h1, h2 = net.hosts[0], net.hosts[1]
            h1.cmd(f"timeout 2 ping -c 1 -W 1 {h2.IP()} > /dev/null 2>&1")
        except Exception:
            pass
    print(f"*** Prueba '{kind}' terminada ({time.time()-t0:.0f}s). "
          f"Eventos en CSV: {_count_events()}", flush=True)
    if summary:
        _print_summary({kind: attackers})   # resumen con % justo sobre el atacante
    if plot:
        # Prueba individual: generar SOLO la gráfica de este tipo.
        try:
            plots.generate_one(kind, EVENTS_CSV)
        except Exception as e:
            print(f"*** Aviso: no se pudo generar la gráfica ({e}). "
                  f"Las métricas están en {EVENTS_CSV}.")
    return attackers


def _count_events():
    """Nº de filas de datos en el CSV de eventos (para ver el progreso)."""
    try:
        with open(EVENTS_CSV) as f:
            return max(0, sum(1 for _ in f) - 1)
    except OSError:
        return 0


def _print_summary(attackers_by_phase=None):
    """Imprime por terminal un resumen legible de la detección por tipo
    de tráfico, leyendo el CSV de eventos.

    Si se pasan los ATACANTES de cada fase (attackers_by_phase: dict
    fase -> lista de IPs), el porcentaje de detección se calcula SOLO
    sobre los flujos que involucran al atacante -que son los que
    realmente son ataque-. Sin ese dato, se calcula sobre todos los
    flujos de la fase (menos representativo: incluye el tráfico de fondo
    legítimo que ocurre durante el ataque, que el modelo -bien- clasifica
    como normal, y que baja artificialmente el porcentaje)."""
    try:
        import csv as _csv
        with open(EVENTS_CSV) as f:
            rows = list(_csv.DictReader(f))
    except OSError:
        return
    if not rows:
        return

    attackers_by_phase = attackers_by_phase or {}
    fases = {}
    for r in rows:
        fases.setdefault(r.get("traffic_phase", "?"), []).append(r)

    print("\n" + "=" * 60)
    print("  RESUMEN DE DETECCIÓN")
    print("=" * 60)
    for fase, evs in fases.items():
        atacantes = set(attackers_by_phase.get(fase, []))
        if fase == "normal":
            # Para normal: acierto = clasificado como normal; error = FP.
            total = len(evs)
            aciertos = sum(1 for e in evs if e.get("predicted_label") == "normal")
            fp = total - aciertos
            pct = aciertos / total * 100 if total else 0
            print(f"  NORMAL   : {pct:5.1f}% clasificado como normal "
                  f"| {fp} falsos positivos | {total} flujos")
        else:
            # Para ataques: si conocemos al atacante, medir SOLO sobre sus
            # flujos (los que son de verdad el ataque); si no, sobre todos.
            if atacantes:
                flujos_ataque = [e for e in evs
                                 if e.get("src") in atacantes or e.get("dst") in atacantes]
            else:
                flujos_ataque = evs
            total = len(flujos_ataque)
            detectados = sum(1 for e in flujos_ataque if e.get("predicted_label") == fase)
            drops = sum(1 for e in evs if e.get("mitigated") == "1")
            pct = detectados / total * 100 if total else 0
            nota = "" if atacantes else " (sobre todo el tráfico de la fase)"
            print(f"  {fase.upper():9s}: {pct:5.1f}% detectado como {fase} "
                  f"| {drops} DROP | {total} flujos del ataque{nota}")
    print("=" * 60 + "\n")


def _run_battery(net):
    # La batería es un experimento propio: empieza borrando TODO (métricas
    # y gráficas anteriores) y encadena los 4 tipos SIN resetear ni
    # graficar entre ellos (plot=False), para que el CSV final contenga
    # las 4 clases. Al terminar genera TODAS las gráficas + las tablas.
    # Cada fase va en su try/except para que un fallo en una no impida
    # las siguientes.
    _reset_all(silent=True)
    print("\n=== BATERÍA COMPLETA: normal -> scanning -> ddos -> spoofing ===")
    attackers_by_phase = {}
    for kind in ["normal", "scanning", "ddos", "spoofing"]:
        try:
            attackers_by_phase[kind] = _run_single(
                net, kind, reset=False, plot=False, summary=False) or []
        except Exception as e:
            print(f"*** Aviso: la fase '{kind}' falló ({e}), continúo con la siguiente.")
            _set_active(False)
        _drain(3)  # dejar que las últimas estadísticas se procesen
    print("\n=== Batería completa terminada. Generando gráficas y tablas... ===")
    _print_summary(attackers_by_phase)   # resumen final con % justo
    # Guardar una copia del CSV completo de la batería (con las 4 clases),
    # para que una prueba individual posterior no lo sobrescriba. Es el
    # CSV que interesa conservar para la memoria.
    try:
        import shutil
        copia = os.path.join(config.PROJECT_ROOT, "results", "metrics",
                             "defense_events_bateria.csv")
        if os.path.exists(EVENTS_CSV):
            shutil.copy(EVENTS_CSV, copia)
            print(f"*** Copia de la batería guardada en {copia}")
    except Exception as e:
        print(f"*** Aviso: no se pudo guardar la copia de la batería ({e}).")
    _make_plots()


def _drain(seconds):
    time.sleep(seconds)


def _make_plots():
    from defense import plots
    try:
        plots.generate_all(EVENTS_CSV)
    except Exception as e:
        print(f"*** Aviso: no se pudieron generar todas las gráficas ({e}).")
        print(f"*** Las métricas están a salvo en {EVENTS_CSV}.")


def _reset_all(silent=False):
    """Borra TODO lo de tandas anteriores: el CSV de eventos, las
    gráficas de la fase 3 y las tablas de la fase 3. Así cada prueba
    (individual o batería) empieza de cero y no se mezclan resultados.
    El controlador repone la cabecera del CSV en el siguiente evento
    (ver _init_events_csv en sdn_defense.py)."""
    import glob
    figs_dir = os.path.join(config.PROJECT_ROOT, "results", "figures", "defense")
    tables_dir = os.path.join(config.PROJECT_ROOT, "results", "tables")
    if os.path.exists(EVENTS_CSV):
        os.remove(EVENTS_CSV)
    for p in glob.glob(os.path.join(figs_dir, "*.png")):
        try:
            os.remove(p)
        except OSError:
            pass
    for p in glob.glob(os.path.join(tables_dir, "defense_*.csv")):
        try:
            os.remove(p)
        except OSError:
            pass
    if not silent:
        print("*** Métricas, gráficas y tablas anteriores borradas.")


# --------------------------------------------------------------------- #
# Menú
# --------------------------------------------------------------------- #
MENU = """
============================================================
  FASE 3 - DETECCIÓN Y MITIGACIÓN (menú)
============================================================
  Cada opción borra los resultados anteriores y genera los suyos.
  Consejo: prueba primero los tipos por separado (1-4). La batería (5)
  encadena los 4 y exige más al entorno.
  1) Tráfico NORMAL   -> genera su gráfica
  2) Tráfico SCANNING -> genera su gráfica
  3) Tráfico DDOS     -> genera su gráfica
  4) Tráfico SPOOFING -> genera su gráfica
  5) BATERÍA COMPLETA -> genera las 4 gráficas + CPU/latencia + tablas
  6) Salir (limpia el entorno: mn -c)
============================================================
"""


def main():
    if os.geteuid() != 0:
        print("Este script necesita sudo (Mininet).")
        sys.exit(1)

    subprocess.run(["mn", "-c"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    _set_active(False)  # asegurar que no queda un flag de una ejecución anterior
    controller_proc = _start_controller()
    net = None
    try:
        net = _build_net()
        print("*** Red lista. El controlador de defensa está clasificando en vivo.")
        while True:
            print(MENU)
            choice = input("Elige una opción [1-6]: ").strip()
            if choice == "1":
                _run_single(net, "normal")
            elif choice == "2":
                _run_single(net, "scanning")
            elif choice == "3":
                _run_single(net, "ddos")
            elif choice == "4":
                _run_single(net, "spoofing")
            elif choice == "5":
                _run_battery(net)
            elif choice == "6":
                break
            else:
                print("Opción no válida.")
    except KeyboardInterrupt:
        print("\n*** Interrumpido por el usuario.")
    finally:
        _cleanup(controller_proc, net)
        print("\n*** Fin de la fase de detección y mitigación.")
        print(f"    Métricas: {EVENTS_CSV}")
        print(f"    Gráficas: {os.path.join('results', 'figures', 'defense')}")


if __name__ == "__main__":
    main()
