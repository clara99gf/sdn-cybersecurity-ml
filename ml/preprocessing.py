#!/usr/bin/env python3
"""
ml/preprocessing.py
-------------------
Prepara dataset_sdn.csv (fase 1) para el entrenamiento. Deja el dataset
limpio y codificado, pero sin escalar ni seleccionar características: eso
se hace dentro de cada fold de la validación cruzada (ml/evaluate.py)
para no filtrar información entre fases. El balanceo de clases tampoco se
toca aquí; se resuelve en ml/train.py con class_weight="balanced".
 
Pasos:
  0. Calcular las 4 características de ventana temporal (patrón entre
     flujos en los últimos WINDOW_SECONDS segundos; ver
     add_temporal_window_features).
  1. Reconstruir la fase de tráfico de cada fila (para agrupar en
     GroupKFold; ver reconstruct_phase_groups).
  2. Quitar las filas de warmup (el pingAll de arranque, que no es
     ninguna de las 4 clases).
  3. Quitar duplicados.
  4. Eliminar identificadores del laboratorio (IP, MAC, timestamp,
     dpid): con solo 16 hosts, el modelo podría memorizarlos en vez de
     aprender patrones de tráfico.
  5. Eliminar columnas constantes de configuración.
  6. Tratar nulos e infinitos: las tasas con indeterminación aritmética
     eliminan la fila; los campos que "no aplican" a un protocolo (un
     flujo UDP no tiene puertos TCP) se rellenan con 0.
  7. Codificar las categóricas (eth_type, ip_proto, arp_opcode,
     tcp_flags) con LabelEncoder.
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

# Ventana temporal (segundos) de las características de patrón entre
# flujos. Se lee de config.py, que el clasificador en vivo usa también
# (deben coincidir). Ver config.WINDOW_SECONDS.
WINDOW_SECONDS = config.WINDOW_SECONDS

# Con False, main() genera el dataset sin las 4 características de ventana
# temporal, para poder comparar el rendimiento con y sin ellas.
INCLUDE_TEMPORAL_WINDOW_FEATURES = True

# Columnas auxiliares que solo sirven para calcular las características de
# ventana; se eliminan después junto con los identificadores.
_WINDOW_HELPER_COLS = ["_src_id", "_dst_id", "_dst_port"]


def add_temporal_window_features(df: pd.DataFrame, window_s: int = WINDOW_SECONDS) -> pd.DataFrame:
    """Añade 4 características de patrón entre flujos, con una ventana que
    mira window_s segundos hacia atrás (nunca al futuro, para no filtrar
    información):
 
      - distinct_ports_by_src: puertos destino distintos por origen; alto
        en escaneo de puertos.
      - distinct_targets_by_src: destinos distintos por origen; alto en
        escaneo de red.
      - flows_to_target: flujos hacia el mismo (destino, puerto); alto
        cuando un servicio recibe mucho tráfico.
      - distinct_sources_to_target: orígenes distintos hacia el mismo
        (destino, puerto); alto en DDoS distribuido. Se cuenta por
        (destino, puerto) y no solo por destino para no confundir con un
        DDoS el tráfico no relacionado hacia otra IP reutilizada.
 
    Usa el WindowTracker compartido con la detección en vivo, de modo que
    la característica se calcula igual al entrenar (modo lote, aquí) y al
    clasificar (evento a evento, en el controlador). ip_src/ip_dst/
    timestamp se usan solo como cálculo intermedio y se eliminan después.
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

    src_port_tracker = WindowTracker(window_s)   # origen  -> puerto destino
    src_dst_tracker = WindowTracker(window_s)    # origen -> destino
    # Clave (destino, puerto), no solo destino: así solo cuenta tráfico
    # hacia el mismo servicio concreto, y no confunde con un DDoS el
    # tráfico hacia otro puerto de una IP reutilizada en otra fase.
    dst_src_tracker = WindowTracker(window_s)

    n = len(df)
    distinct_ports = np.zeros(n, dtype=int)
    distinct_targets = np.zeros(n, dtype=int)
    flows_to_target = np.zeros(n, dtype=int)
    distinct_sources = np.zeros(n, dtype=int)
    # Último recuento de puertos distintos visto por origen, para que
    # las filas sin puerto (ARP/ICMP) hereden el contexto de su origen
    # en vez de romper la señal (ver comentario en el bucle).
    last_ports_by_src = {}

    for i in range(n):
        # El contador de puertos solo se alimenta con filas que tienen
        # puerto real. Las filas sin puerto (ARP/ICMP) heredan el último
        # valor de su origen en vez de contar su relleno -1 como un puerto
        # más, que falsearía el recuento en pleno escaneo.
        if dst_ports[i] >= 0:
            _, distinct_ports[i] = src_port_tracker.add(src_ids[i], dst_ports[i], ts[i])
            last_ports_by_src[src_ids[i]] = distinct_ports[i]
        else:
            distinct_ports[i] = last_ports_by_src.get(src_ids[i], 0)
        _, distinct_targets[i] = src_dst_tracker.add(src_ids[i], dst_ids[i], ts[i])
        total, n_distinct_src = dst_src_tracker.add((dst_ids[i], dst_ports[i]), src_ids[i], ts[i])
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


def clean_nulls_and_infinites(df: pd.DataFrame, groups: np.ndarray = None):
    """Elimina las filas con tasas indeterminadas (inf/NaN) y rellena con 0
    los campos que no aplican al protocolo de la fila. Devuelve (df,
    groups); groups se filtra con la misma máscara que las filas, para que
    no queden desalineados con GroupKFold."""
    # Un inf/NaN en las tasas es una indeterminación aritmética real: se
    # elimina la fila.
    before = len(df)
    df[config.RATE_COLUMNS] = df[config.RATE_COLUMNS].replace([np.inf, -np.inf], np.nan)
    mask = df[config.RATE_COLUMNS].notna().all(axis=1)
    df = df[mask]
    if groups is not None:
        groups = np.asarray(groups)[mask.to_numpy()]
    if before != len(df):
        print(f"[preprocessing] Filas con tasas nulas/infinitas eliminadas: {before - len(df)}")

    # NaN estructural (campos que no aplican al protocolo): no es un dato
    # perdido, se rellena con 0. Eliminar la fila destruiría casi todo el
    # dataset, porque una fila IP nunca tiene campos ARP y viceversa.
    struct_cols = [c for c in config.STRUCTURAL_NA_COLUMNS if c in df.columns]
    df[struct_cols] = df[struct_cols].fillna(0)
    return df, groups


def reconstruct_phase_groups(df: pd.DataFrame) -> np.ndarray:
    """Devuelve la fase de tráfico a la que pertenece cada fila, con la que
    GroupKFold agrupa en la evaluación.
 
    Usa la columna `phase_id`, un contador que traffic_generator.py
    incrementa en cada set_label(). Es un identificador explícito, y no
    los cambios de etiqueta, porque el tipo de fase se sortea y salen
    varias del mismo tipo seguidas: por cambios de etiqueta se fundirían
    en un solo grupo.
 
    Agrupar por fase es necesario porque las filas de una misma fase están
    muy correladas (mismo atacante, misma víctima, segundos de
    diferencia): repartirlas entre train y test inflaría el F1 sin medir
    generalización real (ver evaluate.py).
    """
    if "phase_id" in df.columns:
        df = df.sort_values("timestamp") if not df["timestamp"].is_monotonic_increasing else df
        return df["phase_id"].to_numpy()

    print("[preprocessing] AVISO: el CSV no tiene columna 'phase_id' (tirada "
          "antigua). Reconstruyendo fases por cambios de etiqueta -fases "
          "consecutivas del mismo tipo se fusionarán, dando menos grupos y "
          "una evaluación menos fiable. Regenera el dataset para evitarlo.")
    df = df.sort_values("timestamp") if not df["timestamp"].is_monotonic_increasing else df
    return (df[config.TARGET_COLUMN] != df[config.TARGET_COLUMN].shift()).cumsum().to_numpy()


def encode_categoricals(df: pd.DataFrame) -> tuple:
    """Codifica las columnas categóricas con LabelEncoder. Devuelve el df y
    los encoders ajustados, que la fase 3 reutiliza para codificar igual en
    vivo."""
    encoders = {}
    for col in config.CATEGORICAL_COLUMNS:
        if col not in df.columns:
            continue
        le = LabelEncoder()
        df[col] = le.fit_transform(df[col].astype(str))
        encoders[col] = le
    print(f"[preprocessing] Categóricas codificadas: {list(encoders.keys())}")
    return df, encoders


def summarize_dataset(df: pd.DataFrame, groups) -> pd.DataFrame:
    """Tabla descriptiva del dataset que se va a entrenar: por clase, nº de
    flujos, porcentaje, nº de fases de tráfico distintas (los grupos de la
    validación cruzada) y reparto por protocolo.
 
    Se calcula aquí, justo después de descartar el warmup y los duplicados
    y antes de codificar, que es cuando el dataset ya es el definitivo
    pero las columnas siguen siendo legibles (ip_proto/eth_type sin
    codificar). Se guarda en results/tables/dataset_summary.csv: es la
    tabla que describe el dataset en la memoria."""
    proto = pd.Series("otro", index=df.index)
    proto[df["eth_type"] == 2054] = "arp"
    proto[df["ip_proto"] == 1] = "icmp"
    proto[df["ip_proto"] == 6] = "tcp"
    proto[df["ip_proto"] == 17] = "udp"
    g = pd.Series(groups, index=df.index)
    rows = []
    for clase in sorted(df[config.TARGET_COLUMN].unique()):
        m = df[config.TARGET_COLUMN] == clase
        row = {
            "class": clase,
            "flows": int(m.sum()),
            "share_pct": round(m.mean() * 100, 2),
            # OJO: una misma fase puede aportar flujos de más de una clase
            # (en una fase de ataque también hay ARP/ICMP entre hosts no
            # implicados, que se etiqueta como normal). Por eso la suma de
            # esta columna es mayor que el total de fases.
            "phases_with_class": int(g[m].nunique()),
        }
        for pr in ["arp", "icmp", "tcp", "udp"]:
            row[f"{pr}_pct"] = round((proto[m] == pr).mean() * 100, 1)
        rows.append(row)
    table = pd.DataFrame(rows)
    total = {"class": "total", "flows": int(len(df)), "share_pct": 100.0,
             "phases_with_class": int(pd.Series(groups).nunique())}
    for pr in ["arp", "icmp", "tcp", "udp"]:
        total[f"{pr}_pct"] = round((proto == pr).mean() * 100, 1)
    table = pd.concat([table, pd.DataFrame([total])], ignore_index=True)
    out = os.path.join(config.TABLES_DIR, "dataset_summary.csv")
    table.to_csv(out, index=False)
    print(f"\n[preprocessing] Tabla descriptiva del dataset -> {out}")
    print(table.to_string(index=False))
    return table


def main(include_window_features: bool = INCLUDE_TEMPORAL_WINDOW_FEATURES):
    """Ejecuta el preprocesado completo y guarda (X, y, groups) y los
    encoders. Con include_window_features=False omite las 4 características
    de ventana temporal, para comparar el rendimiento con y sin ellas."""
    df = load_raw_data()

    if include_window_features:
        print(f"\n[preprocessing] Calculando características de ventana temporal ({WINDOW_SECONDS}s)...")
        df = add_temporal_window_features(df)
    else:
        print("\n[preprocessing] Características de ventana temporal DESACTIVADAS "
              "(include_window_features=False).")
        print(f"[preprocessing] AVISO: sobrescribe {config.DATA_PROCESSED_DIR} y "
              f"{config.MODELS_DIR} con la versión sin estas características. Haz "
              f"una copia antes si quieres conservar ambas.")

    df["timestamp"] = pd.to_datetime(df["timestamp"])
    df = df.sort_values("timestamp").reset_index(drop=True)
    print("\n[preprocessing] Reconstruyendo episodios de tráfico (fases) para "
          "la validación cruzada agrupada (ver GroupKFold en evaluate.py)...")
    groups = reconstruct_phase_groups(df)
    print(f"[preprocessing] Fases reconstruidas: {len(set(groups))}")

    df, groups = drop_warmup_rows(df, groups)
    df, groups = drop_duplicates(df, groups)
    summarize_dataset(df, groups)
    df = drop_identifier_columns(df)
    df = drop_constant_columns(df)
    df, groups = clean_nulls_and_infinites(df, groups)
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
    print("[preprocessing] El escalado y la selección de características se "
          "hacen dentro de cada fold (ml/train.py, ml/evaluate.py), no aquí, "
          "para no filtrar información entre fases.")


if __name__ == "__main__":
    main()
