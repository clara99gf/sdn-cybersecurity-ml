# Ejecución

Asume que ya has corrido `./setup.sh` (instalación de dependencias y
creación del venv). Este documento es solo para arrancar el proyecto.

## Opción A — Todo en un comando (recomendado)

```bash
sudo venv/bin/python3 run_01_dataset.py
```

Esto arranca el controlador Ryu, espera a que esté listo, levanta la
topología Mininet, genera el tráfico y al terminar (o con `Ctrl+C`)
detiene el controlador y limpia el estado de Mininet automáticamente.
Si el controlador no llega a arrancar, `run_01_dataset.py` te muestra
directamente en la terminal las últimas líneas de su log — no hace
falta ir a buscarlo aparte.

> **Por qué `sudo venv/bin/python3` y no `sudo python3`**: Mininet
> necesita privilegios de root, y `sudo` por defecto ignora el venv
> activado (resetea el `PATH`). Usando la ruta explícita al Python del
> venv, `sudo` ejecuta ese intérprete con permisos de root sin
> necesidad de activar nada antes ni usar `sudo -E`.

Si no has creado el venv (dependencias instaladas a nivel de sistema):
```bash
sudo python3 run_01_dataset.py
```

## Opción B — Manual, dos terminales (para depurar paso a paso)

**Terminal 1** (controlador):
```bash
sudo ryu-manager controller/sdn_monitor.py
```
(o `sudo venv/bin/ryu-manager ...` SI existe ese archivo -depende de
cómo haya quedado instalado ryu en tu venv concreto-. Compruébalo con
`ls venv/bin/ryu-manager`; si no existe, usa el del sistema como
arriba -`run_01_dataset.py` ya hace esta comprobación automáticamente,
así que con el modo automático nunca hace falta pensar en esto-.)

**Terminal 2** (red + generación de tráfico):
```bash
cd mininet_lab
sudo ../venv/bin/python3 topology.py
```

## Opción C — Prueba manual (red y controlador reales, sin generar el dataset)

Para probar comandos a mano (p.ej. un `nmap` concreto) en el entorno
REAL del proyecto -misma topología, mismo controlador, mismos ajustes
TSO/GSO/GRO- sin lanzar la generación automática de tráfico:

**Terminal 1** (controlador, igual que en la Opción B):
```bash
sudo ryu-manager controller/sdn_monitor.py
```

**Terminal 2**:
```bash
sudo SDN_MANUAL_TEST=1 venv/bin/python3 mininet_lab/topology.py
```
(el orden importa: `sudo VAR=valor comando`, NO `VAR=valor sudo
comando` -sudo borra el entorno de quien lo llama por defecto, así que
la variable tiene que ir DESPUÉS de `sudo`, no antes-.)

Levanta la red y espera en la CLI de Mininet (`mininet>`) en vez de
generar el dataset. Desde ahí, comandos como `h1 nmap -Pn -sS -T4 <IP>`
se ejecutan en el entorno real -a diferencia de una red de Mininet
mínima aparte (`mn --topo ...`), que no tiene el controlador ni los
ajustes del proyecto y puede dar resultados engañosos-.

## Preprocesado, entrenamiento y evaluación (una vez generado el CSV)

**Sin `sudo`**: trabajan sobre el CSV ya generado, no tocan Mininet.
`ml/evaluate.py` tarda algo más que antes (~2-3 min con el dataset de
30k filas): entrena cada modelo 5 veces (validación cruzada agrupada
por fase, ver README.md), no una sola vez.

**Opción A — un solo comando:**
```bash
venv/bin/python3 ml/run_02_ml.py
```

**Opción B — paso a paso (para depurar):**
```bash
venv/bin/python3 ml/preprocessing.py
venv/bin/python3 ml/train.py
venv/bin/python3 ml/evaluate.py
```

Genera `data/processed/` (datos listos para entrenar), `models/`
(modelos y artefactos entrenados) y `results/` (tablas CSV y gráficas
PNG: comparativa de métricas, matrices de confusión, coste
computacional). Detalle de cada paso en `README.md`.

## Dónde queda todo

Todo se guarda dentro del propio proyecto (no en `/tmp`), para que sea
siempre visible con tu usuario normal aunque ejecutes con `sudo`:

- Dataset: `data/dataset_sdn.csv`
- Log del controlador Ryu: `logs/ryu_controller.log`
- Log de la generación de tráfico (útil si una clase no aparece en el
  CSV — revisa aquí primero): `logs/traffic_generator.log`
- Estado efímero compartido (etiqueta activa): `runtime/current_label.txt`
- Datos preprocesados: `data/processed/`
- Modelos y artefactos entrenados: `models/`
- Tablas y gráficas de resultados: `results/tables/`, `results/figures/`

(rutas configurables en `config.py`, raíz del proyecto)

## Si algo se queda "colgado" de una ejecución anterior

```bash
sudo mn -c
sudo pkill -f ryu-manager
```
