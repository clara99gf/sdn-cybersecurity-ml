# Dataset SDN para detección de amenazas (TFG)

Genera un CSV con características de flujos OpenFlow etiquetadas como
`normal`, `scanning`, `spoofing` o `ddos`, a partir de una topología en
árbol emulada en Mininet y controlada por Ryu.

- **Instalación**: `setup.sh`
- **Ejecución**: `EJECUCION.md`
- **Configuración centralizada**: `config.py`

## Estructura

```
config.py                 # Rutas y parámetros compartidos por todo el proyecto
run_all.py                 # Lanza controlador + red + generación con un solo comando
setup.py                    # Instalación editable del proyecto (pip install -e .)
setup.sh                     # Instala dependencias de sistema, crea el venv y ejecuta setup.py
requirements.txt              # Dependencias Python (dentro del venv): ryu, scapy
controller/
  __init__.py
  sdn_monitor.py               # App Ryu: switch L2 + monitor periódico -> CSV
mininet_lab/
  __init__.py
  topology.py                   # Levanta la topología y lanza la generación
  traffic_generator.py          # Orquesta las fases de tráfico intercaladas
  arp_spoof.py                   # Script de spoofing ARP (usado por traffic_generator)
```

> Nota de nombres: la carpeta se llama `mininet_lab/` (no `mininet/`)
> a propósito, para no chocar con el paquete real `mininet` que se
> importa en `topology.py`.

## Sobre `setup.py`

`setup.sh` ya lo instala automáticamente (`pip install -e .` dentro
del venv), así que no tienes que hacer nada extra. Lo que aporta:
convierte el proyecto en un paquete instalado en modo editable, de
forma que `import config`, `from controller import sdn_monitor`, etc.
funcionan de forma nativa desde cualquier sitio -incluido un notebook
de preprocesado/entrenamiento fuera de este árbol de carpetas- sin
depender de la carpeta desde la que ejecutes algo. No es
imprescindible para que `run_all.py` funcione (cada script ya se
resuelve solo con un pequeño `sys.path.insert()` como red de
seguridad), pero es la forma "correcta" de reutilizar `config.py`
-por ejemplo, para leer `CSV_FILE` o `LABEL_FILE`- desde fuera del
proyecto sin repetir rutas a mano.

## Cómo aproximarte a ~12.000 muestras

Cada fila del CSV corresponde a **un flujo activo en un switch en un
instante de sondeo**. El número total de filas depende de (todo
ajustable en `config.py`):

- `POLL_INTERVAL`: cada cuánto se piden estadísticas.
- `TOTAL_DURATION`, `MIN_PHASE_DURATION`, `MAX_PHASE_DURATION`: duración
  total de la simulación y de cada fase.
- `TOPO_DEPTH` / `TOPO_FANOUT`: más hosts = más flujos simultáneos.
- `FLOW_IDLE_TIMEOUT` / `FLOW_HARD_TIMEOUT`: timeouts más cortos ->
  los flujos expiran antes -> se crean más flujos nuevos -> más filas.

Recomendación: haz primero una tanda corta (`TOTAL_DURATION` de 20-30
min), mira cuántas filas obtienes en `/tmp/dataset_sdn.csv` y
extrapola para fijar la duración total que necesitas. Si te sobran
filas, puedes truncar en el preprocesado; si te faltan, sube la
duración o baja los timeouts de flujo.

## Características incluidas en el CSV

Identificación: `timestamp`, `dpid`, MACs, `eth_type`.

Capa 3/4: `ip_src`, `ip_dst`, `ip_proto`, puertos TCP/UDP.

Campos ARP (clave para detectar spoofing): `arp_opcode`, `arp_spa`,
`arp_tpa`, `arp_sha` — permiten ver, por ejemplo, una misma MAC
anunciando IPs distintas o una alta tasa de respuestas ARP no
solicitadas.

Estadísticas del flujo: `duration_sec/nsec`, `idle_timeout`,
`hard_timeout`, `packet_count`, `byte_count`.

Características derivadas (las más útiles para diferenciar clases):
- `packet_count_per_second` / `byte_count_per_second`: muy altos en
  DDoS y en escaneos agresivos.
- `avg_packet_size`: los floods (ICMP/SYN) suelen tener paquetes
  pequeños y homogéneos; el tráfico normal es más variable.
- `flow_count_per_dpid`: un scanning genera muchos flujos de corta
  duración en poco tiempo sobre el mismo switch.

`label`: la clase de la fila (`normal`, `scanning`, `spoofing`, `ddos`),
tomada de la fase de tráfico activa en el momento del muestreo.

## Si una clase no aparece en el CSV

Revisa `/tmp/traffic_generator.log` (o la ruta que pongas en
`TRAFFIC_LOG_FILE` en `config.py`): ahí quedan registrados los
comandos lanzados y sus errores, y al arrancar la generación se avisa
si falta `nmap`, `hping3` o `iperf` en los hosts. El escaneo (`nmap`)
usa siempre `-Pn` para evitar que un descubrimiento de host fallido
haga que nmap se salte el escaneo entero sin avisar.

## Después de generar el CSV

Como ya planeas, aplica el preprocesado (eliminar filas nulas o
incompletas —p. ej. flujos ARP sin campos IP—, normalizar tipos
numéricos, posiblemente balancear clases si alguna fase generó muchas
más filas que otras) antes de entrenar el modelo.
