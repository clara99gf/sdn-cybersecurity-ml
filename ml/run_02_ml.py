#!/usr/bin/env python3
"""
ml/run_02_ml.py
-------------------
Orquestador de la fase de ML: ejecuta preprocessing.py -> train.py ->
evaluate.py en un solo comando, parando en cuanto falle alguno (no
tiene sentido entrenar con datos que no se generaron bien, ni evaluar
modelos que no se entrenaron).

A diferencia de run_01_dataset.py (raíz del proyecto): aquí no hace falta
coordinar procesos independientes (controlador Ryu + Mininet), ni
privilegios de root, ni limpiar estado al terminar -son tres scripts
secuenciales, cada uno leyendo lo que dejó el anterior-. Por eso este
orquestador es mucho más simple: no necesita gestión de procesos ni
señales, solo llamar a cada paso y parar si alguno lanza un error.

Ejecución (sin sudo, a diferencia de run_01_dataset.py):
    venv/bin/python3 ml/run_02_ml.py

Equivale a ejecutar, en este orden:
    venv/bin/python3 ml/preprocessing.py
    venv/bin/python3 ml/train.py
    venv/bin/python3 ml/evaluate.py
"""
import sys
import time

import preprocessing
import train
import evaluate

STEPS = [
    ("Preprocesado", preprocessing.main),
    ("Entrenamiento", train.main),
    ("Evaluación", evaluate.main),
]


def main():
    t_start = time.time()
    for name, step_fn in STEPS:
        print(f"\n{'=' * 60}\n{name}\n{'=' * 60}")
        t0 = time.time()
        try:
            step_fn()
        except Exception as e:
            print(f"\n[ERROR] Fallo en '{name}': {e}")
            print(f"[run_02_ml] Deteniendo -no tiene sentido seguir con el "
                  f"siguiente paso si '{name}' no ha terminado bien-.")
            sys.exit(1)
        print(f"[run_02_ml] '{name}' completado en {time.time() - t0:.1f}s")

    print(f"\n{'=' * 60}\nPipeline de ML completado en {time.time() - t_start:.1f}s.\n{'=' * 60}")


if __name__ == "__main__":
    main()
