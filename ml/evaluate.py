#!/usr/bin/env python3
"""
ml/evaluate.py
--------------
Evalúa los tres modelos con validación cruzada agrupada por fase
(GroupKFold): en cada partición, todas las filas de una misma fase van
juntas a train o a test, nunca repartidas.
 
Se agrupa por fase porque las filas de una misma fase están muy
correladas (mismo atacante, misma víctima, segundos de diferencia): un
split aleatorio por fila dejaría filas casi gemelas a los dos lados, y el
modelo "reconocería" en test fragmentos que ya vio en train, inflando el
F1 sin medir generalización real. Se usan varias particiones, y no un
único split, porque un solo split agrupado es muy inestable según qué
fases caigan en test; promediar varias da una estimación más estable.
 
El escalado y la selección de características se hacen dentro de cada
fold, ajustados solo con su parte de entrenamiento, para que la fuga de
información no reaparezca por esa vía.
 
Genera tres entregables: la tabla y el gráfico de métricas de los tres
modelos (el mejor se elige por F1 macro), una matriz de confusión por
modelo (con predicciones out-of-fold, cada fila predicha por un modelo
que no vio su fase), y la tabla de coste computacional (entrenamiento e
inferencia). Precision/recall/F1 se promedian en "macro", para que todas
las clases pesen igual.
"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import (
    accuracy_score, precision_score, recall_score, f1_score,
    precision_recall_fscore_support, confusion_matrix, ConfusionMatrixDisplay,
)
from sklearn.model_selection import GroupKFold
from sklearn.preprocessing import StandardScaler
from sklearn.tree import DecisionTreeClassifier

from ml.utils import load_full_dataset, load_artifact, save_artifact

N_CV_FOLDS = 5

MODEL_CTORS = {
    "logistic_regression": lambda: LogisticRegression(
        class_weight="balanced", max_iter=2000, random_state=config.RANDOM_STATE,
    ),
    "decision_tree": lambda: DecisionTreeClassifier(
        class_weight="balanced", random_state=config.RANDOM_STATE,
    ),
    "random_forest": lambda: RandomForestClassifier(
        class_weight="balanced", n_estimators=200,
        random_state=config.RANDOM_STATE, n_jobs=-1,
    ),
}
MODEL_NAMES = {
    "logistic_regression": "Logistic Regression",
    "decision_tree": "Decision Tree",
    "random_forest": "Random Forest",
}


def select_features_for_fold(X_train_scaled: pd.DataFrame, y_train) -> list:
    """Devuelve las N_FEATURES más importantes según un Random Forest
    ajustado solo con los datos de entrenamiento de este fold."""
    rf = RandomForestClassifier(
        n_estimators=200, random_state=config.RANDOM_STATE,
        class_weight="balanced", n_jobs=-1,
    )
    rf.fit(X_train_scaled, y_train)
    importances = pd.Series(rf.feature_importances_, index=X_train_scaled.columns)
    return importances.sort_values(ascending=False).head(config.N_FEATURES).index.tolist()


def cross_validate_model(model_ctor, X, y, groups, n_splits=N_CV_FOLDS):
    """GroupKFold: entrena y evalúa el modelo en n_splits particiones,
    sin que ninguna fase quede repartida entre train y test dentro de
    un mismo fold. Devuelve las predicciones "out-of-fold" (cada fila
    predicha exactamente una vez) y las métricas por fold."""
    gkf = GroupKFold(n_splits=n_splits)
    oof_pred = np.full(len(y), -1)
    per_fold_metrics = []
    per_flow_inference_times = []

    for fold_i, (train_idx, test_idx) in enumerate(gkf.split(X, y, groups=groups), start=1):
        X_train, X_test = X.iloc[train_idx], X.iloc[test_idx]
        y_train, y_test = y[train_idx], y[test_idx]

        scaler = StandardScaler()
        X_train_s = pd.DataFrame(scaler.fit_transform(X_train), columns=X.columns)
        X_test_s = pd.DataFrame(scaler.transform(X_test), columns=X.columns)

        selected = select_features_for_fold(X_train_s, y_train)
        X_train_sel, X_test_sel = X_train_s[selected], X_test_s[selected]

        model = model_ctor()
        model.fit(X_train_sel, y_train)

        t0 = time.time()
        y_pred = model.predict(X_test_sel)
        inference_time = time.time() - t0
        per_flow_inference_times.append(inference_time / len(X_test_sel))

        oof_pred[test_idx] = y_pred
        fold_f1 = f1_score(y_test, y_pred, average="macro", zero_division=0)
        per_fold_metrics.append(fold_f1)
        print(f"    fold {fold_i}/{n_splits}: F1 = {fold_f1:.4f} "
              f"(train={len(train_idx)}, test={len(test_idx)})")

    return oof_pred, per_fold_metrics, per_flow_inference_times


def per_class_metrics(y_true, y_pred, class_names, model_display_name):
    """Precision, recall, F1 y nº de muestras por clase, a partir de las
    predicciones out-of-fold. Complementa las métricas macro: muestra qué
    ataque se detecta mejor o peor, y es directamente comparable con la
    tabla por clase de la detección en vivo (fase 3)."""
    p, r, f, n = precision_recall_fscore_support(
        y_true, y_pred, labels=range(len(class_names)), zero_division=0)
    return pd.DataFrame({
        "model": model_display_name,
        "class": class_names,
        "precision": p.round(4),
        "recall": r.round(4),
        "f1": f.round(4),
        "support": n,
    })


def plot_metrics_bar(metrics_df, out_path):
    ax = metrics_df.set_index("model")[["accuracy", "precision", "recall", "f1"]].plot(
        kind="bar", figsize=(9, 5), rot=0,
    )
    ax.set_ylabel("Puntuación (media GroupKFold)")
    ax.set_title("Comparativa de métricas por modelo (validación cruzada agrupada por fase)")
    ax.set_ylim(0, max(1.0, metrics_df[["accuracy", "precision", "recall", "f1"]].values.max() * 1.1))
    ax.legend(loc="lower right")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def plot_confusion_matrix(cm, class_names, model_display_name, out_path):
    fig, ax = plt.subplots(figsize=(6, 5))
    disp = ConfusionMatrixDisplay(confusion_matrix=cm, display_labels=class_names)
    disp.plot(ax=ax, cmap="Blues", colorbar=False, xticks_rotation=45)
    ax.set_title(f"Matriz de confusión (out-of-fold) - {model_display_name}")
    plt.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def plot_cost_bar(cost_df, out_path):
    """Coste computacional por modelo, en dos paneles con su propia escala
    (entrenamiento en segundos, inferencia en ms por flujo), porque son
    unidades distintas y compararlas entre sí no tendría sentido. La
    inferencia va en escala logarítmica: entre modelos hay dos órdenes de
    magnitud, y en lineal los dos rápidos serían invisibles."""
    fig, (ax1, ax2) = plt.subplots(1, 2, figsize=(11, 4.5))
    models = cost_df["model"]
    ax1.bar(models, cost_df["training_time_s"], color="#2980b9")
    ax1.set_ylabel("Segundos")
    ax1.set_title("Tiempo de entrenamiento (dataset completo)")
    ax2.bar(models, cost_df["inference_time_ms_per_flow"], color="#e67e22")
    ax2.set_yscale("log")
    ax2.set_ylabel("ms por flujo (escala log)")
    ax2.set_title("Tiempo de inferencia")
    for ax in (ax1, ax2):
        ax.tick_params(axis="x", rotation=15)
        ax.grid(axis="y", alpha=0.25)
    fig.suptitle("Coste computacional por modelo")
    fig.tight_layout()
    plt.savefig(out_path, dpi=150)
    plt.close()


def main():
    """Evalúa los tres modelos con GroupKFold y guarda las tablas, las
    matrices de confusión, la comparativa de coste y el mejor modelo
    (best_model.pkl)."""
    X, y, groups = load_full_dataset()
    le_y = load_artifact("le_y.pkl")
    class_names = list(le_y.classes_)
    print(f"[evaluate] Dataset: {X.shape[0]} filas, {len(set(groups))} fases, "
          f"validación cruzada agrupada con {N_CV_FOLDS} particiones\n")

    try:
        training_times = load_artifact("training_times.pkl")
    except FileNotFoundError:
        print("[evaluate] AVISO: no se encontró training_times.pkl "
              "(ejecuta ml/train.py primero). La columna de tiempo de "
              "entrenamiento quedará vacía.")
        training_times = {}

    rows, cost_rows, per_class_rows = [], [], []
    for key, display_name in MODEL_NAMES.items():
        print(f"[evaluate] {display_name}: validación cruzada agrupada por fase...")
        oof_pred, fold_f1s, per_flow_times = cross_validate_model(
            MODEL_CTORS[key], X, y, groups,
        )

        metrics = {
            "accuracy": accuracy_score(y, oof_pred),
            "precision": precision_score(y, oof_pred, average="macro", zero_division=0),
            "recall": recall_score(y, oof_pred, average="macro", zero_division=0),
            "f1": f1_score(y, oof_pred, average="macro", zero_division=0),
            "f1_std_entre_folds": float(np.std(fold_f1s)),
        }
        rows.append({"model": display_name, **metrics})
        cost_rows.append({
            "model": display_name,
            "training_time_s": training_times.get(key, float("nan")),
            "inference_time_ms_per_flow": float(np.mean(per_flow_times)) * 1000,
        })

        per_class_rows.append(per_class_metrics(y, oof_pred, class_names, display_name))

        cm = confusion_matrix(y, oof_pred)
        plot_confusion_matrix(
            cm, class_names, display_name,
            os.path.join(config.FIGURES_DIR, f"confusion_matrix_{key}.png"),
        )
        print(f"[evaluate] {display_name}: F1 medio={metrics['f1']:.4f} "
              f"(±{metrics['f1_std_entre_folds']:.4f} entre folds)\n")

    metrics_df = pd.DataFrame(rows)
    cost_df = pd.DataFrame(cost_rows)

    per_class_df = pd.concat(per_class_rows, ignore_index=True)
    per_class_df.to_csv(os.path.join(config.TABLES_DIR, "metrics_by_class.csv"), index=False)

    metrics_df.to_csv(os.path.join(config.TABLES_DIR, "metrics_comparison.csv"), index=False)
    cost_df.to_csv(os.path.join(config.TABLES_DIR, "computational_cost.csv"), index=False)

    plot_metrics_bar(metrics_df, os.path.join(config.FIGURES_DIR, "metrics_comparison.png"))
    plot_cost_bar(cost_df, os.path.join(config.FIGURES_DIR, "computational_cost.png"))

    best_row = metrics_df.sort_values("f1", ascending=False).iloc[0]
    best_key = [k for k, v in MODEL_NAMES.items() if v == best_row["model"]][0]
    best_model = load_artifact(f"{best_key}.pkl")
    save_artifact(best_model, "best_model.pkl")

    print(f"\n[evaluate] Mejor modelo según F1-score medio (GroupKFold, macro): "
          f"{best_row['model']} (F1={best_row['f1']:.4f} ± {best_row['f1_std_entre_folds']:.4f}) "
          f"-> guardado como models/best_model.pkl")

    print("\n=== Tabla de métricas (media entre folds) ===")
    print(metrics_df.to_string(index=False))
    print("\n=== Tabla de coste computacional ===")
    print(cost_df.to_string(index=False))
    print(f"\n=== Métricas por clase del mejor modelo ({best_row['model']}) ===")
    print(per_class_df[per_class_df["model"] == best_row["model"]]
          .drop(columns="model").to_string(index=False))
    print("    (las de los tres modelos, en "
          f"{os.path.join(config.TABLES_DIR, 'metrics_by_class.csv')})")


if __name__ == "__main__":
    main()
