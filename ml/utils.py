"""
ml/utils.py
-----------
Funciones de persistencia del pipeline de ML: guardar y cargar el
dataset procesado (X, y, groups) y los artefactos entrenados (modelos,
scaler, encoders...).
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
    """Guarda el dataset ya limpio y codificado (X, y, groups), sin dividir,
    escalar ni seleccionar características: eso se hace dentro de cada fold
    (ver ml/evaluate.py). 'groups' indica la fase de cada fila, para
    GroupKFold."""
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


# Alias más explícitos para cuando el objeto guardado es un modelo.
save_model = save_artifact
load_model = load_artifact


def load_artifacts() -> Tuple[Any, list, Any, dict]:
    """Carga en bloque los 4 artefactos que necesita la inferencia: scaler,
    características seleccionadas, encoder de la etiqueta y encoders de las
    categóricas."""
    artifact_files = ["scaler.pkl", "selected_features.pkl", "le_y.pkl", "encoders.pkl"]
    return tuple(load_artifact(fn) for fn in artifact_files)
