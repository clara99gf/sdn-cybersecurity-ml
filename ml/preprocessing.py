#!/usr/bin/env python3
"""
ml/preprocessing.py
--------------------
Preprocesado del dataset_sdn.csv (generado por run_01_dataset.py) para
entrenar Logistic Regression, Decision Tree y Random Forest.

Pasos (en este orden, y por qué):
  0. Calcular características de VENTANA TEMPORAL (5s hacia atrás en
     el tiempo, sin fuga de información): puertos y destinos distintos
     tocados por el mismo origen, y cuántos flujos/orígenes distintos
     han llegado al mismo destino, en los últimos 5s. Una fila aislada
     no puede ver esto -es el PATRÓN entre flujos lo que distingue
     mejor los ataques entre sí (muchos puertos/destinos desde un
     origen = escaneo; muchos orígenes a un destino = DDoS
     distribuido)-. Usa ip_src/ip_dst/timestamp SOLO como cálculo
     intermedio -esas columnas se descartan después igual que
     siempre-. Se calcula con `feature_windows.WindowTracker`, un
     módulo COMPARTIDO (no exclusivo de este script): se usa aquí en
     modo lote (recorriendo el CSV ya ordenado por tiempo), y la
     misma clase se reutilizará sin cambios cuando se aborde la fase
     de detección en vivo, alimentada evento a evento desde el
     controlador -evitando que el cálculo "en entrenamiento" y "en
     producción" diverjan (training-serving skew)-. Se calcula en
     preprocessing ("offline") y no en el generador SDN porque no hace
     falta regenerar el dataset de Mininet/Ryu (ya validado en muchas
     rondas) para iterar sobre esto, y la metodología del TFG ya pide
     evaluación offline.
  1. Quitar las filas de warmup (pingAll de arranque; no representa
     ninguna de las 4 clases que se quieren clasificar).
  2. Filtrar duplicados.
  3. Eliminar identificadores rígidos (IP, MAC, timestamp, dpid): con
     solo 16 hosts y 5 switches en el laboratorio, el modelo podría
     memorizar qué IP/MAC concretas aparecen en qué clase en vez de
     aprender patrones de tráfico generalizables.
  4. Filtrar valores nulos/infinitos derivados de indeterminaciones en
     las métricas de tráfico (packet_count_per_second,
     byte_count_per_second, avg_packet_size). OJO: esto es distinto
     del NaN "estructural" que aparece en puertos/campos ARP según el
     protocolo de cada fila (un flujo UDP no tiene tcp_dst_port) -eso
     NO es un dato corrupto, así que no se elimina la fila, se rellena
     con 0 (ver STRUCTURAL_NA_COLUMNS)-.
  5. Codificación numérica de variables categóricas (eth_type,
     ip_proto, arp_opcode) con LabelEncoder.
  6. Reconstruir a qué "fase" (episodio de tráfico) pertenece cada
     fila, a partir de los cambios de la propia etiqueta en orden
     temporal. NECESARIO para poder evaluar con GroupKFold en
     ml/evaluate.py: las filas de una misma fase están muy correladas
     entre sí (mismo atacante, misma víctima, segundos de diferencia),
     así que un split aleatorio por fila (que reparte filas de la
     MISMA fase entre train y test) infla el rendimiento medido de
     forma artificial -el modelo "reconoce" fragmentos casi idénticos
     de un ataque que ya vio en parte durante el entrenamiento, no
     está generalizando a un ataque nuevo de verdad. Comprobado
     empíricamente: con split aleatorio por fila el F1 de Random
     Forest salía en 0.777; agrupando por fase completa (ninguna fase
     repartida entre train y test) baja a ~0.46 -ESTE es el número que
     refleja de verdad la capacidad de generalización a un ataque
     nunca visto-.

NOTA IMPORTANTE sobre el escalado y la selección de características:
ya NO se hacen aquí. Antes se hacían una única vez, sobre un solo
split -pero eso mismo filtraba información entre fases de train y
test igual que el problema de arriba-. Ahora se hacen DENTRO de cada
fold de la validación cruzada agrupada (ver ml/evaluate.py), ajustando
el scaler y seleccionando características solo con los datos de
entrenamiento de ESE fold.

El balanceo de clases NO se toca aquí: se aplica en ml/train.py vía
class_weight="balanced" en los propios modelos -una solución
algorítmica e integrada en scikit-learn, no una manipulación de los
datos (nada de sobremuestreo/duplicado de filas)-.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
import config
from feature_windows import WindowTracker

import numpy as np
import pandas as pd
from sklearn.preprocessing import LabelEncoder

from ml.utils import save_artifact, save_full_dataset

# Ventana temporal (segundos) para las características de patrón entre
# flujos. 5s es del orden de POLL_INTERVAL (2s) y FLOW_IDLE_TIMEOUT
# (3s) del generador -mucho más corta apenas vería más de 1 flujo;
# mucho más larga empieza a mezclar fases distintas del generador-.
WINDOW_SECONDS = 5

# Interruptor para poder reproducir la comparación "con vs. sin
# características de ventana temporal" (ablation study) cuando se
# quiera, sin tener que editar el código -solo cambiar esta variable
# (o pasar include_window_features=False a main())-.
INCLUDE_TEMPORAL_WINDOW_FEATURES = True

# Columnas auxiliares SOLO para calcular las features de ventana
# temporal -se añaden a los identificadores a eliminar después-.
_WINDOW_HELPER_COLS = ["_src_id", "_dst_id", "_dst_port"]


def add_temporal_window_features(df: pd.DataFrame, window_s: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Añade 4 características de PATRÓN entre flujos (no de un flujo
    aislado), con una ventana deslizante hacia atrás de window_s
    segundos (nunca mira al futuro respecto al timestamp de cada fila
    -sin fuga de información-):

      - distinct_ports_by_src_{w}s: nº de puertos destino distintos
        tocados por el mismo origen -alto en escaneo de puertos-.
      - distinct_targets_by_src_{w}s: nº de destinos distintos tocados
        por el mismo origen -alto en escaneo de red (cambia de host
        objetivo, no solo de puerto)-.
      - flows_to_target_{w}s: nº de flujos hacia el mismo destino
        -alto cuando un objetivo recibe mucho tráfico-.
      - distinct_sources_to_target_{w}s: nº de orígenes distintos que
        han apuntado al mismo destino -alto en DDoS distribuido
        (muchos atacantes, una víctima)-.

    Usa WindowTracker (ver feature_windows.py), la MISMA clase que se
    reutilizará en la futura fase de detección en vivo -aquí se
    alimenta fila a fila en orden temporal (modo lote); en el
    controlador se alimentaría evento a evento en tiempo real-, para
    que el cálculo de las features sea idéntico en entrenamiento y en
    producción.

    ip_src/ip_dst/timestamp se usan SOLO aquí como cálculo intermedio;
    drop_identifier_columns() las elimina después como siempre.
    """
    df = df.copy()
    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)

    # Identidad de origen/destino unificada independientemente del
    # protocolo (IP para tráfico IP, MAC/arp_tpa para ARP).
    df["_src_id"] = df["ip_src"].fillna(df["eth_src"])
    df["_dst_id"] = df["ip_dst"].fillna(df["arp_tpa"])
    df["_dst_port"] = df["tcp_dst_port"].fillna(df["udp_dst_port"]).fillna(-1)

    ts = df["timestamp"].apply(lambda t: t.timestamp()).to_numpy()
    src_ids = df["_src_id"].to_numpy()
    dst_ids = df["_dst_id"].to_numpy()
    dst_ports = df["_dst_port"].to_numpy()

    src_port_tracker = WindowTracker(window_s)   # clave: origen  -> valor: puerto destino
    src_dst_tracker = WindowTracker(window_s)    # clave: origen  -> valor: destino
    dst_src_tracker = WindowTracker(window_s)    # clave: destino -> valor: origen

    n = len(df)
    distinct_ports = np.zeros(n, dtype=int)
    distinct_targets = np.zeros(n, dtype=int)
    flows_to_target = np.zeros(n, dtype=int)
    distinct_sources = np.zeros(n, dtype=int)

    for i in range(n):
        _, distinct_ports[i] = src_port_tracker.add(src_ids[i], dst_ports[i], ts[i])
        _, distinct_targets[i] = src_dst_tracker.add(src_ids[i], dst_ids[i], ts[i])
        total, n_distinct_src = dst_src_tracker.add(dst_ids[i], src_ids[i], ts[i])
        flows_to_target[i] = total
        distinct_sources[i] = n_distinct_src

    suffix = f"_{window_s}s"
    df[f"distinct_ports_by_src{suffix}"] = distinct_ports
    df[f"distinct_targets_by_src{suffix}"] = distinct_targets
    df[f"flows_to_target{suffix}"] = flows_to_target
    df[f"distinct_sources_to_target{suffix}"] = distinct_sources

    return df


def load_raw_data(path: str = None) -> pd.DataFrame:
    path = path or config.CSV_FILE
    if not os.path.exists(path):
        raise FileNotFoundError(
            f"[ERROR] No se encontró '{path}'. Genera primero el dataset con "
            f"run_01_dataset.py (ver EJECUCION.md)."
        )
    df = pd.read_csv(path)
    print(f"[preprocessing] Filas cargadas: {len(df)}")
    return df


def drop_warmup_rows(df: pd.DataFrame, groups: np.ndarray = None):
    before = len(df)
    mask = (df[config.TARGET_COLUMN] != "warmup").to_numpy()
    df = df[mask].reset_index(drop=True)
    print(f"[preprocessing] Filas 'warmup' eliminadas: {before - len(df)} "
          f"({len(df)} filas restantes)")
    if groups is not None:
        return df, groups[mask]
    return df


def drop_duplicates(df: pd.DataFrame, groups: np.ndarray = None):
    before = len(df)
    keep_mask = ~df.duplicated()
    df = df[keep_mask].reset_index(drop=True)
    print(f"[preprocessing] Duplicados eliminados: {before - len(df)} "
          f"({len(df)} filas restantes)")
    if groups is not None:
        return df, groups[keep_mask.to_numpy()]
    return df


def drop_identifier_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols_present = [c for c in (config.ID_COLUMNS + _WINDOW_HELPER_COLS) if c in df.columns]
    print(f"[preprocessing] Eliminando identificadores rígidos: {cols_present}")
    return df.drop(columns=cols_present)


def drop_constant_columns(df: pd.DataFrame) -> pd.DataFrame:
    cols_present = [c for c in config.CONSTANT_COLUMNS if c in df.columns]
    print(f"[preprocessing] Eliminando columnas constantes (config, no tráfico): {cols_present}")
    return df.drop(columns=cols_present)


def clean_nulls_and_infinites(df: pd.DataFrame) -> pd.DataFrame:
    # Infinitos en las tasas derivadas (indeterminaciones aritméticas
    # reales) -> se tratan como NaN y esas filas se eliminan.
    before = len(df)
    df[config.RATE_COLUMNS] = df[config.RATE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    df = df.dropna(subset=config.RATE_COLUMNS)
    if before != len(df):
        print(f"[preprocessing] Filas con tasas nulas/infinitas eliminadas: {before - len(df)}")

    # NaN ESTRUCTURAL (puertos/campos ARP que no aplican a ese
    # protocolo): NO es un dato perdido, se rellena con 0 en vez de
    # eliminar la fila -eliminar destruiría casi todo el dataset, ya
    # que una fila IP nunca tiene campos ARP y viceversa-.
    struct_cols = [c for c in config.STRUCTURAL_NA_COLUMNS if c in df.columns]
    df[struct_cols] = df[struct_cols].fillna(0)
    return df


def reconstruct_phase_groups(df: pd.DataFrame) -> np.ndarray:
    """Reconstruye a qué "fase" (episodio de tráfico) pertenece cada fila,
    a partir de los cambios de la propia etiqueta en orden temporal -cada
    vez que traffic_generator.py llama a set_label() empieza una fase
    nueva, así que un cambio de label = una fase nueva-.

    Necesario para evaluar con GroupKFold (ver evaluate.py): las filas de
    una MISMA fase están muy correladas entre sí (mismo atacante, misma
    víctima, segundos de diferencia) -si el split de train/test las
    reparte al azar entre las dos, el modelo puede "reconocer" en test
    fragmentos casi idénticos de un ataque que ya vio en train, inflando
    el F1 de forma artificial sin medir generalización real a un ataque
    nuevo-. Agrupando por fase y sin repartir ninguna entre train y test,
    se evita ese problema.
    """
    df = df.sort_values("timestamp") if not df["timestamp"].is_monotonic_increasing else df
    return (df[config.TARGET_COLUMN] != df[config.TARGET_COLUMN].shift()).cumsum().to_numpy()


def encode_categoricals(df: pd.DataFrame) -> tuple:
    encoders = {}
    for col in config.CATEGORICAL_COLUMNS:
        if col not in df.columns:
            continue
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    print(f"[preprocessing] Categóricas codificadas: {list(encoders.keys())}")
    return df, encoders


def main(include_window_features: bool = INCLUDE_TEMPORAL_WINDOW_FEATURES):
    df = load_raw_data()

    if include_window_features:
        print(f"\n[preprocessing] Calculando características de ventana temporal ({WINDOW_SECONDS}s)...")
        df = add_temporal_window_features(df)
    else:
        print("\n[preprocessing] Características de ventana temporal DESACTIVADAS "
              "(include_window_features=False) -para comparar con/sin-.")
        print(f"[preprocessing] AVISO: esto va a SOBRESCRIBIR los resultados en "
              f"{config.DATA_PROCESSED_DIR} y {config.MODELS_DIR} con la versión "
              f"SIN estas características -no se guarda en ningún sitio aparte-. "
              f"Si quieres conservar ambas versiones, haz una copia antes o usa un "
              f"script aparte (como se hizo para la comparación con/sin).")

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    print("\n[preprocessing] Reconstruyendo episodios de tráfico (fases) para "
          "la validación cruzada agrupada (ver GroupKFold en evaluate.py)...")
    groups = reconstruct_phase_groups(df)
    print(f"[preprocessing] Fases reconstruidas: {len(set(groups))}")

    df, groups = drop_warmup_rows(df, groups)
    df, groups = drop_duplicates(df, groups)
    df = drop_identifier_columns(df)
    df = drop_constant_columns(df)
    df = clean_nulls_and_infinites(df)
    df, encoders = encode_categoricals(df)

    y_raw = df[config.TARGET_COLUMN]
    X = df.drop(columns=[config.TARGET_COLUMN])

    le_y = LabelEncoder()
    y = le_y.fit_transform(y_raw)
    print("\n[preprocessing] Clases detectadas:")
    for idx, class_name in enumerate(le_y.classes_):
        print(f"    [{idx}] {class_name}: {(y_raw == class_name).sum()} muestras")

    save_full_dataset(X, y, groups)
    save_artifact(le_y, "le_y.pkl")
    save_artifact(encoders, "encoders.pkl")

    print(f"\n[preprocessing] Preprocesado completado. {X.shape[0]} filas, "
          f"{X.shape[1]} columnas, {len(set(groups))} fases (grupos).")
    print("[preprocessing] NOTA: el escalado y la selección de características "
          "se hacen ahora dentro de cada fold de la validación cruzada, no "
          "aquí -para no filtrar información entre fases de train y test-. "
          "Ver ml/train.py y ml/evaluate.py.")


if __name__ == "__main__":
    main()
