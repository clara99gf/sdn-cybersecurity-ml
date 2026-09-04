#!/usr/bin/env python3
"""
ml/train.py
-----------
Ajusta el pipeline FINAL desplegable (escalado + selección de las
N_FEATURES características más relevantes + modelo) para Logistic
Regression, Decision Tree y Random Forest, entrenando sobre TODO el
dataset disponible.

IMPORTANTE - por qué sobre TODO el dataset y no sobre un 80%:
Este script no mide rendimiento (eso lo hace ml/evaluate.py, con
validación cruzada agrupada por fase -GroupKFold-, evitando que se
mezclen filas de la misma fase entre "entrenamiento" y "prueba"). Este
script solo produce el modelo que se guardaría para usar de verdad:
para ESO, cuantos más datos históricos use para aprender, mejor -no
hay ningún motivo para reservarse un 20% sin usar en el modelo final,
la única razón para "reservar" datos es medir rendimiento, que ya se
hace aparte-.

El balanceo de clases se resuelve AQUÍ, con class_weight="balanced" en
los tres modelos -no en el preprocesado-: los algoritmos penalizan más
los errores en las clases minoritarias durante el entrenamiento, sin
duplicar ni destruir ninguna fila real del dataset (alternativa
algorítmica al sobremuestreo manual).
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml.utils import load_full_dataset, save_artifact

MODELS = {
    "logistic_regression": LogisticRegression(
        class_weight="balanced", max_iter=2000, random_state=config.RANDOM_STATE,
    ),
    "decision_tree": DecisionTreeClassifier(
        class_weight="balanced", random_state=config.RANDOM_STATE,
    ),
    "random_forest": RandomForestClassifier(
        class_weight="balanced", n_estimators=200,
        random_state=config.RANDOM_STATE, n_jobs=-1,
    ),
}


def select_features_by_importance(X_scaled: pd.DataFrame, y) -> list:
    """Ajusta un Random Forest SOLO para estimar la importancia de cada
    característica y quedarse con las N_FEATURES más relevantes."""
    rf = RandomForestClassifier(
        n_estimators=200, random_state=config.RANDOM_STATE,
        class_weight="balanced", n_jobs=-1,
    )
    rf.fit(X_scaled, y)
    importances = pd.Series(rf.feature_importances_, index=X_scaled.columns)
    selected = importances.sort_values(ascending=False).head(config.N_FEATURES).index.tolist()
    print(f"[train] Características seleccionadas ({len(selected)} de {X_scaled.shape[1]}):")
    for feat in selected:
        print(f"    * {feat:<28} (importancia: {importances[feat]:.4f})")
    return selected


def main():
    X, y, groups = load_full_dataset()
    print(f"[train] Dataset completo: {X.shape[0]} filas, {X.shape[1]} columnas, "
          f"{len(set(groups))} fases")

    scaler = StandardScaler()
    X_scaled = pd.DataFrame(scaler.fit_transform(X), columns=X.columns)
    selected_features = select_features_by_importance(X_scaled, y)
    X_final = X_scaled[selected_features]

    save_artifact(scaler, "scaler.pkl")
    save_artifact(selected_features, "selected_features.pkl")

    training_times = {}
    for name, model in MODELS.items():
        print(f"[train] Entrenando {name} (modelo final, sobre todo el dataset)...")
        t0 = time.time()
        model.fit(X_final, y)
        elapsed = time.time() - t0
        training_times[name] = elapsed
        print(f"[train]   -> {elapsed:.4f}s")
        save_artifact(model, f"{name}.pkl")

    save_artifact(training_times, "training_times.pkl")
    print("\n[train] Entrenamiento completado.")
    print(training_times)


if __name__ == "__main__":
    main()
