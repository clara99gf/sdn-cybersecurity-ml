#!/usr/bin/env python3
"""
ml/train.py
-----------
Ajusta el pipeline desplegable (escalado + selección de las N_FEATURES
características más importantes + modelo) para los tres modelos y guarda
los artefactos que usan evaluate.py y la fase 3.
 
Entrena sobre TODO el dataset, no sobre un 80%, porque aquí no se mide
rendimiento (eso lo hace evaluate.py con validación cruzada): este script
solo produce el modelo final, y para eso cuantos más datos, mejor.
 
El balanceo de clases se resuelve con class_weight="balanced" en los tres
modelos: penaliza más los errores en las clases minoritarias durante el
entrenamiento, sin duplicar ni eliminar filas.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
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


def save_feature_importances(importances: pd.Series, selected: list) -> None:
    """Guarda la importancia de cada característica (Random Forest) como
    tabla y gráfico. Es un resultado en sí mismo: muestra en qué se fija el
    modelo y ayuda a explicar por qué unas clases se detectan mejor."""
    table = pd.DataFrame({
        "feature": importances.index,
        "importance": importances.round(5).values,
        "selected": [f in selected for f in importances.index],
    }).sort_values("importance", ascending=False).reset_index(drop=True)
    out_csv = os.path.join(config.TABLES_DIR, "feature_importances.csv")
    table.to_csv(out_csv, index=False)

    top = table.head(config.N_FEATURES).iloc[::-1]
    fig, ax = plt.subplots(figsize=(8, 0.35 * len(top) + 1.5))
    ax.barh(top["feature"], top["importance"], color="#2980b9")
    ax.set_xlabel("Importancia (Random Forest)")
    ax.set_title(f"Características más relevantes (las {config.N_FEATURES} "
                 f"seleccionadas de {len(table)})")
    fig.tight_layout()
    out_png = os.path.join(config.FIGURES_DIR, "feature_importances.png")
    fig.savefig(out_png, dpi=150)
    plt.close(fig)
    print(f"[train] Importancia de características -> {out_csv} y {out_png}")


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
    save_feature_importances(importances, selected)
    return selected


def main():
    """Escala, selecciona características y entrena los tres modelos sobre
    todo el dataset, guardando cada modelo y los artefactos (scaler,
    características seleccionadas, tiempos de entrenamiento)."""
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
