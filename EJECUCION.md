# Ejecución

Requisito previo (una sola vez): `./setup.sh`, que instala las
dependencias y crea el entorno virtual `venv/`.

Las fases 1 y 3 usan Mininet y necesitan `sudo`. Se lanzan siempre con
`sudo venv/bin/python3 ...` (y no con `sudo python3`), porque `sudo`
ignora el venv activado; con la ruta explícita se usa el Python del venv
con permisos de root.

El orden importa: cada fase consume lo que deja la anterior. La 2
necesita el CSV de la 1, y la 3 necesita los modelos de la 2. Si solo
quieres revisar los resultados, el repositorio ya los trae generados y
no hace falta ejecutar nada.

## Fase 1: generación del dataset

```bash
sudo venv/bin/python3 run_01_dataset.py
```

Arranca el controlador Ryu (`controller/sdn_monitor.py`), levanta la
topología, genera fases de tráfico aleatorias hasta alcanzar
`TARGET_ROWS` (300.000 filas, unas 4 horas) y al terminar, o con
`Ctrl+C`, detiene el controlador y limpia Mininet. Si el controlador no
arranca, muestra en la terminal las últimas líneas de su log.

Genera `data/dataset_sdn.csv`. El tamaño y la duración se ajustan en
`config.py` (`TARGET_ROWS`, `TOTAL_DURATION`).

**Prueba manual** (red y controlador reales, sin generar el dataset),
útil para lanzar comandos a mano desde la CLI de Mininet:

```bash
# Terminal 1
sudo venv/bin/ryu-manager controller/sdn_monitor.py
# Terminal 2 (la variable va DESPUÉS de sudo)
sudo SDN_MANUAL_TEST=1 venv/bin/python3 mininet_lab/topology.py
```

## Fase 2: preprocesado, entrenamiento y evaluación

Sin `sudo` (trabaja sobre el CSV, no usa Mininet):

```bash
venv/bin/python3 ml/run_02_ml.py
```

Equivale a ejecutar en orden `ml/preprocessing.py`, `ml/train.py` y
`ml/evaluate.py` (se pueden lanzar por separado para depurar). Tarda
unos tres minutos.

Genera `data/processed/`, los modelos en `models/` (incluido
`best_model.pkl`, el que usa la fase 3) y, en `results/tables/` y
`results/figures/`:

| Fichero | Qué contiene |
|---|---|
| `dataset_summary.csv` | Descripción del dataset: flujos, fases y protocolos por clase |
| `feature_importances.csv` / `.png` | Importancia de cada característica y cuáles se seleccionaron |
| `metrics_comparison.csv` / `.png` | Accuracy, precisión, recall y F1 de los tres modelos |
| `metrics_by_class.csv` | Precisión, recall y F1 por clase, de cada modelo |
| `confusion_matrix_*.png` | Una matriz de confusión por modelo (predicciones out-of-fold) |
| `computational_cost.csv` / `.png` | Tiempo de entrenamiento y de inferencia por modelo |

## Fase 3: detección y mitigación en vivo

Requiere haber ejecutado antes la fase 2 (artefactos en `models/`).

```bash
sudo venv/bin/python3 run_03_defense.py
```

Arranca el controlador de defensa (`controller/sdn_defense.py`) y la red.
Antes del menú hace dos `pingAll`: el primero es de calentamiento (puebla
las cachés ARP y hace que el controlador aprenda las MAC) y el segundo es
la comprobación real, que debe salir con 0 % de pérdida.

| Opción | Qué hace |
|---|---|
| 1-4 | Prueba individual de 30 s con un solo tipo de tráfico (normal, scanning, ddos o spoofing): resumen en terminal y su gráfica |
| 5 | Batería completa: los cuatro tipos seguidos, repetidos `DEFENSE_BATTERY_RUNS` veces (10 por defecto, unos 25 minutos). Resumen global, todas las gráficas y las tablas |
| 6 | Salir limpiando el entorno |

Cada nueva prueba borra los resultados anteriores de la fase 3. La duración de
las pruebas y los parámetros de la mitigación están en la sección
"Fase 3" de `config.py`.

### Resultados de la fase 3

**Registro por flujo** (`results/events/`):

| Fichero | Qué contiene |
|---|---|
| `defense_events.csv` | Un evento por flujo clasificado: predicción, etiqueta real, tiempo de inferencia, latencia, CPU y si se aplicó DROP. Lo reescribe cualquier prueba |
| `defense_events_battery.csv` | Copia de la última batería completa. Idéntico al anterior justo después de lanzar la opción 5; se diferencia en cuanto se lanza una prueba individual, que sobrescribe `defense_events.csv` pero no esta copia |

**Tablas** (`results/tables/`). Las dos primeras responden preguntas
distintas: la detección mide si el modelo acierta
la etiqueta de cada flujo; la mitigación, si el controlador bloquea lo
que debe. Se separan porque el bloqueo altera el tráfico que se está
midiendo.

| Fichero | Qué contiene |
|---|---|
| `defense_detection_by_class.csv` | **Detección**: precisión, recall y F1 por clase, por flujo. Comparable con la fase 2 |
| `defense_mitigation_by_conversation.csv` | **Mitigación**: conversaciones de ataque bloqueadas, conversaciones legítimas bloqueadas por error, nº de DROP y tiempo hasta el primer bloqueo |
| `defense_recall_around_drop.csv` | Recall por flujo antes y después del primer DROP: explica por qué las dos tablas anteriores dan números distintos |
| `defense_battery_runs.csv` | Métricas macro de cada ejecución de la batería, con media y desviación |
| `defense_infrastructure_by_traffic.csv` | CPU de Ryu, latencia del plano de control y tiempos de inferencia por tipo de tráfico |

**Figuras** (`results/figures/defense/`):

| Fichero | Qué contiene |
|---|---|
| `confusion_matrix_live.png` | Matriz de confusión de la detección en vivo, con todas las ejecuciones |
| `offline_vs_live_by_class.png` | Recall y F1 por clase, offline frente a en vivo |
| `scanning_ports.png`, `spoofing_detected.png` | Flujos reales del ataque frente a los detectados por el modelo, acumulados, con los instantes de bloqueo |
| `ddos_pkt_rate.png` | Tasa de paquetes del DDoS: se ve el ataque cortado tras el DROP y su reaparición al expirar la regla |
| `normal_pkt_rate.png` | Tasa de paquetes del tráfico legítimo con los bloqueos erróneos marcados |
| `cpu_vs_latency.png` | CPU de Ryu y latencia del plano de control durante cada tipo de prueba |

Para regenerar gráficas y tablas desde un CSV ya recogido, sin volver a
lanzar la red:

```bash
venv/bin/python3 defense/plots.py results/events/defense_events_battery.csv
```

## Dónde queda cada cosa

| Qué | Dónde |
|---|---|
| Dataset | `data/dataset_sdn.csv` |
| Datos procesados | `data/processed/` |
| Modelos | `models/` |
| Tablas y figuras | `results/tables/`, `results/figures/` |
| Eventos de la fase 3 (un registro por flujo clasificado) | `results/events/` |
| Logs del controlador | `logs/ryu_controller.log` (fase 1), `logs/ryu_defense.log` (fase 3) |
| Logs del tráfico | `logs/traffic_generator.log` (fase 1), `logs/defense_traffic.log` (fase 3) |
| Ficheros de coordinación | `runtime/` |

## Si algo se queda colgado

```bash
sudo mn -c
sudo pkill -f ryu-manager
```