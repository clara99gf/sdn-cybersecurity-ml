# Ejecución

Requisito previo (una sola vez): `./setup.sh`, que instala las
dependencias y crea el entorno virtual `venv/`.

Las fases 1 y 3 usan Mininet y necesitan `sudo`. Se lanzan siempre con
`sudo venv/bin/python3 ...` (y no con `sudo python3`), porque `sudo`
ignora el venv activado; con la ruta explícita se usa el Python del venv
con permisos de root.

## Fase 1: generación del dataset

```bash
sudo venv/bin/python3 run_01_dataset.py
```

Arranca el controlador Ryu (`controller/sdn_monitor.py`), levanta la
topología, genera fases de tráfico aleatorias hasta alcanzar
`TARGET_ROWS` (300.000 filas, unas 5 horas) y al terminar, o con
`Ctrl+C`, detiene el controlador y limpia Mininet. Si el controlador no
arranca, muestra en la terminal las últimas líneas de su log.

Genera `data/dataset_sdn.csv`. El tamaño y la duración se ajustan en
`config.py` (`TARGET_ROWS`, `TOTAL_DURATION`); hay valores comentados
para tiradas de prueba cortas.

**Prueba manual** (red y controlador reales, sin generar el dataset),
útil para lanzar comandos a mano desde la CLI de Mininet:

```bash
# Terminal 1
sudo venv/bin/ryu-manager controller/sdn_monitor.py
# Terminal 2 (la variable va DESPUÉS de sudo)
sudo SDN_MANUAL_TEST=1 venv/bin/python3 mininet_lab/topology.py
```

Si no existe `venv/bin/ryu-manager` (depende de cómo se instalara Ryu),
usa `sudo ryu-manager ...`.

## Fase 2: preprocesado, entrenamiento y evaluación

Sin `sudo` (trabaja sobre el CSV, no usa Mininet):

```bash
venv/bin/python3 ml/run_02_ml.py
```

Equivale a ejecutar en orden `ml/preprocessing.py`, `ml/train.py` y
`ml/evaluate.py` (se pueden lanzar por separado para depurar).

Genera `data/processed/`, los modelos en `models/` (incluido
`best_model.pkl`, el que usa la fase 3) y, en `results/tables/` y
`results/figures/`:

- `dataset_summary.csv`: descripción del dataset (flujos, fases y
  protocolos por clase).
- `feature_importances.csv` y `.png`: en qué se fija el modelo.
- `metrics_comparison.csv` y `.png`: comparativa de los tres modelos.
- `metrics_by_class.csv`: precision, recall y F1 por clase de cada modelo.
- `confusion_matrix_*.png`: una matriz por modelo.
- `computational_cost.csv` y `.png`: entrenamiento e inferencia.

## Fase 3: detección y mitigación en vivo

Requiere haber ejecutado antes la fase 2 (artefactos en `models/`).

```bash
sudo venv/bin/python3 run_03_defense.py
```

Arranca el controlador de defensa (`controller/sdn_defense.py`) y la red,
y abre un menú:

| Opción | Qué hace |
|---|---|
| 1-4 | Prueba individual de 30 s con un solo tipo de tráfico (normal, scanning, ddos o spoofing): resumen en terminal y su gráfica |
| 5 | Batería completa: los cuatro tipos seguidos, repetidos `DEFENSE_BATTERY_RUNS` veces (10 por defecto, unos 25 minutos). Resumen global con F1 y recall macro (media ± desviación entre ejecuciones), todas las gráficas y las tablas |
| 6 | Salir limpiando el entorno |

Cada opción borra los resultados anteriores de la fase 3. La duración de
las pruebas y los parámetros de la mitigación están en la sección
"Fase 3" de `config.py`.

Resultados:

- `results/events/defense_events.csv`: un evento por flujo clasificado
  (predicción, etiqueta real, inferencia, latencia, CPU, DROP).
- `results/events/defense_events_battery.csv`: copia de la última
  batería, que no se sobrescribe con las pruebas individuales.
- `results/figures/defense/`: gráficas por tipo de tráfico y de CPU
  frente a latencia (de la ejecución representativa de la batería: la de
  F1 macro más cercano a la media) y matriz de confusión en vivo (de
  todas las ejecuciones).
- `results/tables/`: `defense_detection_by_class.csv` (precision, recall
  y F1 por clase), `defense_battery_runs.csv` (métricas de cada
  ejecución, con media y desviación) y
  `defense_infrastructure_by_traffic.csv` (CPU de Ryu, latencia del plano
  de control y tiempos de inferencia por tipo de tráfico).

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

Todo se guarda dentro del proyecto (no en `/tmp`) para que sea visible
con el usuario normal aunque se ejecute con `sudo`. Las rutas se
configuran en `config.py`.

## Si algo se queda colgado

```bash
sudo mn -c
sudo pkill -f ryu-manager
```

Si una clase de tráfico no aparece, revisa primero el log de tráfico de
la fase correspondiente: ahí quedan los comandos lanzados y sus errores.
