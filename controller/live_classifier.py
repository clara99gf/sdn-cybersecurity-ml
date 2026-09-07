"""
live_classifier.py
------------------
Clasificador de flujos EN VIVO para la fase de detección y mitigación.

Reproduce EXACTAMENTE el mismo preprocesado que ml/preprocessing.py
(mismas columnas, mismo orden, mismos LabelEncoders, mismo StandardScaler
y misma selección de características), pero aplicado flujo a flujo en
tiempo real en vez de en lote sobre un CSV. Así, un flujo se clasifica
en detección igual que se habría clasificado durante el entrenamiento.

Las 4 características de ventana temporal se calculan con el MISMO módulo
compartido (feature_windows.WindowTracker) que usa el preprocesado; aquí
los WindowTracker se alimentan en cada sondeo del controlador, no en
lote. Esto garantiza que la feature "distinct_ports_by_src_5s" (etc.)
signifique lo mismo en entrenamiento y en detección.

Carga los artefactos que guarda ml/train.py:
    - <model>.pkl        (best_model.pkl por defecto)
    - scaler.pkl
    - selected_features.pkl
    - encoders.pkl       (LabelEncoders de las categóricas)
    - le_y.pkl           (LabelEncoder de la etiqueta -> nombres de clase)
"""
import os
import time

import numpy as np
import pandas as pd

import config
from feature_windows import WindowTracker
from ml.utils import load_artifact

# Orden EXACTO de columnas tal y como las ve el modelo tras el
# preprocesado (ver ml/preprocessing.py). Debe coincidir una a una.
FEATURE_ORDER = [
    "eth_type", "ip_proto", "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port", "tcp_flags", "ip_mac_consistent",
    "arp_unsolicited_reply", "arp_opcode", "duration_sec", "duration_nsec",
    "packet_count", "byte_count", "packet_count_per_second",
    "byte_count_per_second", "avg_packet_size", "flow_count_per_dpid",
    "distinct_ports_by_src_5s", "distinct_targets_by_src_5s",
    "flows_to_target_5s", "distinct_sources_to_target_5s",
]

# Valor de relleno para huecos estructurales numéricos (mismo criterio
# que preprocessing.py: puertos/ARP que no aplican -> 0 tras el
# fillna(0) que hace el preprocesado sobre STRUCTURAL_NA_COLUMNS).
FILL = 0


class LiveClassifier:
    def __init__(self, model_name="best_model.pkl", window_s=None):
        self.window_s = window_s if window_s is not None else 5
        # best_model.pkl lo crea ml/evaluate.py (el mejor de los 3). Si
        # aún no se ha ejecutado la evaluación, se recurre a
        # random_forest.pkl, que es el que suele ganar.
        try:
            self.model = load_artifact(model_name)
        except FileNotFoundError:
            self.model = load_artifact("random_forest.pkl")
        self.scaler = load_artifact("scaler.pkl")
        self.selected_features = load_artifact("selected_features.pkl")
        self.encoders = load_artifact("encoders.pkl")
        self.le_y = load_artifact("le_y.pkl")

        # WindowTrackers en vivo (mismos que preprocessing.py, ver allí
        # el porqué de cada clave/valor).
        self._src_port = WindowTracker(self.window_s)   # origen -> puerto dst
        self._src_dst = WindowTracker(self.window_s)    # origen -> destino
        self._dst_src = WindowTracker(self.window_s)    # (destino,puerto) -> origen
        self._last_ports_by_src = {}

    # -- codificación de categóricas igual que en el preprocesado -------
    def _encode_categorical(self, col, value):
        """Aplica el LabelEncoder entrenado. Si aparece una categoría no
        vista en entrenamiento, usa 0 (clase más frecuente aprox.) en
        vez de fallar -robusto ante variantes nuevas en detección-."""
        le = self.encoders.get(col)
        if le is None:
            return value
        s = str(value)
        classes = list(le.classes_)
        if s in classes:
            return int(le.transform([s])[0])
        return 0

    def _window_features(self, src_id, dst_id, dst_port, now):
        """Calcula las 4 features de ventana temporal alimentando los
        WindowTrackers, exactamente como preprocessing.py."""
        if dst_port is not None and dst_port >= 0:
            _, distinct_ports = self._src_port.add(src_id, dst_port, now)
            self._last_ports_by_src[src_id] = distinct_ports
        else:
            distinct_ports = self._last_ports_by_src.get(src_id, 0)
        _, distinct_targets = self._src_dst.add(src_id, dst_id, now)
        flows_to_target, distinct_sources = self._dst_src.add(
            (dst_id, dst_port), src_id, now
        )
        return distinct_ports, distinct_targets, flows_to_target, distinct_sources

    def build_feature_row(self, raw, now=None):
        """Construye el vector de características de UN flujo a partir de
        un dict 'raw' con los mismos campos crudos que escribiría el
        controlador al CSV. Devuelve un DataFrame de una fila, ya
        codificado, escalado y con solo las características seleccionadas
        -listo para model.predict()-.
        """
        now = now if now is not None else time.time()

        # Identificadores para las ventanas (IP o, si es ARP, la IP ARP).
        src_id = raw.get("ip_src") or raw.get("arp_spa") or "?"
        dst_id = raw.get("ip_dst") or raw.get("arp_tpa") or "?"
        dst_port = raw.get("tcp_dst_port")
        if dst_port is None:
            dst_port = raw.get("udp_dst_port")
        dst_port = int(dst_port) if dst_port not in (None, "") else -1

        dports, dtargets, f2t, dsources = self._window_features(
            src_id, dst_id, dst_port, now
        )

        row = {
            "eth_type": self._encode_categorical("eth_type", raw.get("eth_type", 0)),
            "ip_proto": self._encode_categorical("ip_proto", raw.get("ip_proto", 0)),
            "tcp_src_port": _num(raw.get("tcp_src_port")),
            "tcp_dst_port": _num(raw.get("tcp_dst_port")),
            "udp_src_port": _num(raw.get("udp_src_port")),
            "udp_dst_port": _num(raw.get("udp_dst_port")),
            "tcp_flags": self._encode_categorical("tcp_flags", raw.get("tcp_flags", 0)),
            "ip_mac_consistent": _num(raw.get("ip_mac_consistent")),
            "arp_unsolicited_reply": _num(raw.get("arp_unsolicited_reply")),
            "arp_opcode": self._encode_categorical("arp_opcode", raw.get("arp_opcode", 0)),
            "duration_sec": _num(raw.get("duration_sec")),
            "duration_nsec": _num(raw.get("duration_nsec")),
            "packet_count": _num(raw.get("packet_count")),
            "byte_count": _num(raw.get("byte_count")),
            "packet_count_per_second": _num(raw.get("packet_count_per_second")),
            "byte_count_per_second": _num(raw.get("byte_count_per_second")),
            "avg_packet_size": _num(raw.get("avg_packet_size")),
            "flow_count_per_dpid": _num(raw.get("flow_count_per_dpid")),
            "distinct_ports_by_src_5s": dports,
            "distinct_targets_by_src_5s": dtargets,
            "flows_to_target_5s": f2t,
            "distinct_sources_to_target_5s": dsources,
        }
        df = pd.DataFrame([[row[c] for c in FEATURE_ORDER]], columns=FEATURE_ORDER)
        # Escalar con el scaler del entrenamiento y quedarse con las
        # características seleccionadas, en su orden.
        scaled = pd.DataFrame(self.scaler.transform(df), columns=FEATURE_ORDER)
        return scaled[self.selected_features]

    def predict(self, raw, now=None):
        """Clasifica un flujo. Devuelve (nombre_clase, tiempo_inferencia_ms)."""
        X = self.build_feature_row(raw, now)
        t0 = time.perf_counter()
        pred = self.model.predict(X)[0]
        infer_ms = (time.perf_counter() - t0) * 1000.0
        label = self.le_y.inverse_transform([pred])[0]
        return label, infer_ms


def _num(v):
    """Convierte a número; huecos/vacíos -> FILL (0), igual que el
    fillna(0) del preprocesado sobre columnas de NaN estructural."""
    if v is None or v == "":
        return FILL
    try:
        return float(v)
    except (TypeError, ValueError):
        return FILL
