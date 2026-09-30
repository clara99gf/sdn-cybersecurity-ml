#!/usr/bin/env python3
"""
ml/run_02_ml.py
---------------
Orquestador de la fase 2: ejecuta preprocessing -> train -> evaluate en
un solo comando y se detiene en cuanto uno falla.
 
    venv/bin/python3 ml/run_02_ml.py    (sin sudo; ver EJECUCION.md)
"""
import sys
import time
import traceback

import preprocessing
import train
import evaluate

STEPS = [
    ("Preprocesado", preprocessing.main),
    ("Entrenamiento", train.main),
    ("Evaluación", evaluate.main),
]


def main():
    """Ejecuta los tres pasos en orden, cronometrándolos, y aborta con el
    traceback completo si alguno falla."""
    t_start = time.time()
    for name, step_fn in STEPS:
        print(f"\n{'=' * 60}\n{name}\n{'=' * 60}")
        t0 = time.time()
        try:
            step_fn()
        except Exception as e:
            print(f"\n[ERROR] Fallo en '{name}': {e}")
            # Traza completa: sin ella, un error solo dice el mensaje y no
            # dónde se produjo.
            traceback.print_exc()
            print(f"[run_02_ml] Deteniendo: no tiene sentido seguir si "
                  f"'{name}' no terminó bien.")
            sys.exit(1)
        print(f"[run_02_ml] '{name}' completado en {time.time() - t0:.1f}s")

    print(f"\n{'=' * 60}\nPipeline de ML completado en {time.time() - t_start:.1f}s.\n{'=' * 60}")


if __name__ == "__main__":
    main()
