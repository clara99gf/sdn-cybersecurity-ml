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
`best_model.pkl`, el que usa la fase 3) y las tablas y figuras en
`results/tables/` y `results/figures/`.

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
| 5 | Batería completa: los cuatro tipos seguidos, con resumen global (F1 macro), todas las gráficas y las tablas |
| 6 | Salir limpiando el entorno |

Cada opción borra los resultados anteriores de la fase 3. La duración de
las pruebas y los parámetros de la mitigación están en la sección
"Fase 3" de `config.py`.

Resultados:

- `results/metrics/defense_events.csv`: un evento por flujo clasificado
  (predicción, etiqueta real, inferencia, latencia, CPU, DROP).
- `results/metrics/defense_events_battery.csv`: copia de la última
  batería, que no se sobrescribe con las pruebas individuales.
- `results/figures/defense/`: gráficas por tipo de tráfico, CPU frente a
  latencia y matriz de confusión en vivo.
- `results/tables/defense_*.csv`: detección por clase, CPU y latencia,
  tiempos de inferencia.

Para regenerar gráficas y tablas desde un CSV ya recogido, sin volver a
lanzar la red:

```bash
venv/bin/python3 defense/plots.py results/metrics/defense_events_battery.csv
```

## Dónde queda cada cosa

| Qué | Dónde |
|---|---|
| Dataset | `data/dataset_sdn.csv` |
| Datos procesados | `data/processed/` |
| Modelos | `models/` |
| Tablas y figuras | `results/tables/`, `results/figures/` |
| Métricas de la fase 3 | `results/metrics/` |
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
