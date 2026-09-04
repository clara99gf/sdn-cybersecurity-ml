"""
ml/utils.py
-----------
Utilidades de persistencia para el pipeline de preprocesado /
entrenamiento / evaluación: guardar y cargar los conjuntos de datos
procesados (CSV/NPY) y los artefactos (modelos, scaler, encoders...).

Adaptado del utils.py original de Clara: mismo comportamiento, solo se
cambia "from config.config import ..." por "import config" para que
encaje con el estilo de este proyecto (config.py es un módulo suelto
en la raíz, no un paquete config/config.py).
"""
import os
from typing import Any, Tuple

import joblib
import numpy as np
import pandas as pd

import config


# -------------------------------------------------------------------------
# Datos Procesados (CSV / NPY)
# -------------------------------------------------------------------------

def save_full_dataset(X: pd.DataFrame, y: np.ndarray, groups: np.ndarray) -> None:
    """Guarda el dataset completo ya limpio/codificado (SIN dividir en
    train/test, SIN escalar, SIN seleccionar características -eso se hace
    dentro de cada fold de la validación cruzada, ver ml/evaluate.py-),
    junto con 'groups' (a qué fase/episodio pertenece cada fila, para
    GroupKFold)."""
    os.makedirs(config.DATA_PROCESSED_DIR, exist_ok=True)
    X.to_csv(os.path.join(config.DATA_PROCESSED_DIR, "X.csv"), index=False)
    np.save(os.path.join(config.DATA_PROCESSED_DIR, "y.npy"), y)
    np.save(os.path.join(config.DATA_PROCESSED_DIR, "groups.npy"), groups)
    print(f"[+] Dataset completo guardado en: {config.DATA_PROCESSED_DIR}")


def load_full_dataset() -> Tuple[pd.DataFrame, np.ndarray, np.ndarray]:
    """Carga el dataset completo (X, y, groups) guardado por preprocessing.py."""
    try:
        X = pd.read_csv(os.path.join(config.DATA_PROCESSED_DIR, "X.csv"))
        y = np.load(os.path.join(config.DATA_PROCESSED_DIR, "y.npy"))
        groups = np.load(os.path.join(config.DATA_PROCESSED_DIR, "groups.npy"))
        return X, y, groups
    except FileNotFoundError as e:
        raise FileNotFoundError(
            f"[ERROR] No se encontró el dataset procesado en '{config.DATA_PROCESSED_DIR}': {e}. "
            f"Asegúrate de ejecutar 'ml/preprocessing.py' primero."
        )


# -------------------------------------------------------------------------
# Serialización de Objetos (.pkl)
# -------------------------------------------------------------------------

def save_artifact(obj: Any, filename: str) -> None:
    """Guarda cualquier objeto (modelo, scaler, encoder) en la carpeta models/."""
    os.makedirs(config.MODELS_DIR, exist_ok=True)
    path = os.path.join(config.MODELS_DIR, filename)
    joblib.dump(obj, path)
    print(f"[+] Objeto guardado en: {path}")


def load_artifact(filename: str) -> Any:
    """Carga cualquier objeto (modelo, scaler, encoder) desde la carpeta models/."""
    path = os.path.join(config.MODELS_DIR, filename)
    if not os.path.exists(path):
        raise FileNotFoundError(f"[ERROR] El archivo '{filename}' no existe en '{config.MODELS_DIR}'.")
    return joblib.load(path)


# Alias semánticos para mantener compatibilidad total
save_model = save_artifact
load_model = load_artifact


def load_artifacts() -> Tuple[Any, list, Any, dict]:
    """Carga en bloque los 4 artefactos principales de preprocesamiento para inferencia."""
    artifact_files = ["scaler.pkl", "selected_features.pkl", "le_y.pkl", "encoders.pkl"]
    return tuple(load_artifact(fn) for fn in artifact_files)
