# Ejecución

Asume que ya has corrido `./setup.sh` (instalación de dependencias y
creación del venv). Este documento es solo para arrancar el proyecto.

## Opción A — Todo en un comando (recomendado)

```bash
sudo venv/bin/python3 run_all.py
```

Esto arranca el controlador Ryu, espera a que esté listo, levanta la
topología Mininet, genera el tráfico y al terminar (o con `Ctrl+C`)
detiene el controlador y limpia el estado de Mininet automáticamente.

> **Por qué `sudo venv/bin/python3` y no `sudo python3`**: Mininet
> necesita privilegios de root, y `sudo` por defecto ignora el venv
> activado (resetea el `PATH`). Usando la ruta explícita al Python del
> venv, `sudo` ejecuta ese intérprete con permisos de root sin
> necesidad de activar nada antes ni usar `sudo -E`.

Si no has creado el venv (dependencias instaladas a nivel de sistema):
```bash
sudo python3 run_all.py
```

## Opción B — Manual, dos terminales (para depurar paso a paso)

**Terminal 1** (controlador):
```bash
sudo venv/bin/ryu-manager controller/sdn_monitor.py
```

**Terminal 2** (red + generación de tráfico):
```bash
cd mininet_lab
sudo ../venv/bin/python3 topology.py
```

## Dónde queda todo

- Dataset: `/tmp/dataset_sdn.csv`
- Log del controlador Ryu: `/tmp/ryu_controller.log`
- Log de la generación de tráfico (útil si una clase no aparece en el
  CSV — revisa aquí primero): `/tmp/traffic_generator.log`

(rutas configurables en `config.py`, raíz del proyecto)

## Si algo se queda "colgado" de una ejecución anterior

```bash
sudo mn -c
sudo pkill -f ryu-manager
```
