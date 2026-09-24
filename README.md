# Detección y mitigación de amenazas en SDN con Machine Learning (TFG)

Sistema que combina Redes Definidas por Software (SDN) e Inteligencia
Artificial para detectar y mitigar en tiempo real ataques de **scanning**,
**spoofing** (ARP e IP) y **DDoS** en una red emulada con Mininet y
controlada por Ryu (OpenFlow 1.3).

El proyecto se divide en tres fases:

| Fase | Script | Qué hace | Resultado |
|---|---|---|---|
| 1. Dataset | `run_01_dataset.py` | Genera tráfico normal y de ataque en Mininet y registra las estadísticas de flujo que ve el controlador, etiquetadas por flujo | `data/dataset_sdn.csv` |
| 2. Machine Learning | `ml/run_02_ml.py` | Preprocesa, entrena Logistic Regression, Decision Tree y Random Forest, y los evalúa con validación cruzada agrupada por fase | `models/`, `results/` |
| 3. Detección y mitigación | `run_03_defense.py` | El controlador clasifica cada flujo en vivo con el mejor modelo y bloquea las conversaciones de ataque con reglas OpenFlow DROP | `results/events/`, `results/figures/defense/`, `results/tables/` |

- **Instalación**: `./setup.sh` (Ubuntu; instala Mininet, Open vSwitch,
  nmap, hping3, iperf y crea el entorno virtual con Ryu, scapy y
  scikit-learn).
- **Ejecución paso a paso**: [`EJECUCION.md`](EJECUCION.md).
- **Parámetros**: todos centralizados en `config.py`, con una sección por fase.

## Entorno

- Topología en árbol (profundidad 2, fanout 4): 5 switches y 16 hosts,
  enlaces de 10 Mbps.
- Controlador Ryu con reglas reactivas granulares (una regla por flujo)
  y sondeo de estadísticas cada segundo.
- Tráfico normal: `ping` e `iperf` TCP/UDP. Ataques: `nmap` y sondas ACK
  con `hping3` (scanning), `hping3` SYN/UDP/ICMP con varios atacantes
  (DDoS), envenenamiento ARP con scapy e IP spoofing con `hping3 -a`
  (spoofing).

## Resultados

Resumen; el detalle está en `results/` (tablas CSV y figuras) y el
análisis completo, en la memoria del TFG.

**Fase 2 (evaluación offline).** Dataset de 293.157 flujos y 920 fases,
validación cruzada `GroupKFold` de 5 particiones. Gana **Random Forest**,
con un **F1 macro de 0.797 ± 0.018**, frente a 0.715 del árbol de decisión
y 0.565 de la regresión logística. Las características más determinantes
son el número de flujos activos en el switch y las de ventana temporal
(orígenes y destinos distintos en los últimos 5 s).

**Fase 3 (detección y mitigación en vivo).** Diez repeticiones de la
batería completa, con el mismo criterio de etiqueta que en la fase 2:
**F1 macro de 0.757 ± 0.039**, con un recall macro de 0.767 frente al
0.774 offline. Los tres ataques se mitigan **en torno a 1 s** desde el
primer flujo detectado, con una latencia del controlador de 10-11 ms de
media y un coste de inferencia de 0.8-2 ms por flujo. El coste de los
falsos positivos son unas 5 conversaciones legítimas bloqueadas 20 s por
batería (1.2 % de los flujos normales).

## Decisiones de diseño principales

- **Etiquetado por flujo**: cada ataque declara sus actores (atacante,
  víctimas, identidad suplantada) y solo los flujos que los involucran,
  en ambos sentidos, se etiquetan como ataque.
- **Evaluación sin fuga de información**: `GroupKFold` agrupado por fase,
  con escalado y selección de características dentro de cada partición.
- **Mismo cálculo en entrenamiento y en vivo**: la fase 3 reutiliza el
  generador de tráfico de la fase 1, el mismo cálculo de contadores y
  tasas del monitor, el mismo módulo de ventanas temporales
  (`feature_windows.py`) y el mismo criterio de etiquetado, para evitar
  diferencias entre lo que el modelo vio al entrenar y lo que ve en vivo.
- **Mitigación por conversación**: se bloquea el par MAC origen → MAC
  destino, en todos los switches, tras confirmarlo en dos sondeos, y
  con una regla temporal (20 s). Así un falso positivo corta una
  conversación durante un tiempo acotado, no un host entero.

## Limitaciones conocidas

- Las fases de ataque se generan sin tráfico legítimo concurrente.
- El criterio de actores incluye a la víctima: en DDoS y spoofing, un
  flujo entre la víctima y un host ajeno también contaría como ataque.
- La tasa de un flujo recién instalado se estima como paquetes/edad, lo
  que da picos irreales cuando el flujo tiene milisegundos (igual en el
  dataset y en vivo, así que es coherente con el entrenamiento).
- La vinculación IP↔MAC de referencia (`ip_mac_consistent`) se toma de
  Mininet; en una red real vendría de DHCP o de un inventario.
- En IP spoofing, la mitigación puede cortar temporalmente alguna
  conversación del host cuya IP se falsifica.

## Estructura

```
config.py               Parámetros y rutas de todo el proyecto
feature_windows.py      Ventana temporal deslizante (compartida por fases 2 y 3)
run_01_dataset.py       Fase 1: controlador + red + generación del dataset
run_03_defense.py       Fase 3: menú de detección y mitigación en vivo
setup.sh / setup.py     Instalación (dependencias de sistema, venv, pip install -e .)
controller/
  sdn_monitor.py        Fase 1: app Ryu que registra y etiqueta los flujos
  sdn_defense.py        Fase 3: app Ryu que clasifica en vivo y mitiga
  live_classifier.py    Fase 3: preprocesado idéntico al del entrenamiento, flujo a flujo
mininet_lab/
  topology.py           Fase 1: topología Mininet
  traffic_generator.py  Tráfico normal y de ataque (fases 1 y 3)
  arp_spoof.py          ARP spoofing multi-víctima (scapy)
ml/
  preprocessing.py      Limpieza, ventanas temporales, codificación
  train.py              Entrenamiento de los tres modelos
  evaluate.py           GroupKFold, métricas, matrices de confusión, coste
  run_02_ml.py          Fase 2 completa en un comando
  utils.py              Guardado y carga de datos y modelos
defense/
  traffic.py            Fase 3: lanza el tráfico de cada prueba
  plots.py              Fase 3: gráficas y tablas de resultados
data/                   Dataset (dataset_sdn.csv) y datos procesados
models/                 Modelos entrenados (se generan, no se versionan)
results/                Métricas, tablas y figuras de las fases 2 y 3
logs/, runtime/         Logs y ficheros de coordinación entre procesos
```

## Ficheros versionados

`data/dataset_sdn.csv` se incluye en el repositorio porque generarlo
lleva varias horas. Los modelos (`models/*.pkl`) y los datos procesados
no se incluyen: se regeneran en unos minutos con `ml/run_02_ml.py`
(además, `random_forest.pkl` supera el límite de tamaño de GitHub).
`results/` sí se incluye, como evidencia directa de los resultados.
