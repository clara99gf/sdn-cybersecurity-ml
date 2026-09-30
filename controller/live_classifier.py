"""
controller/live_classifier.py
-----------------------------
Clasificador de flujos en vivo de la fase 3. Reproduce el mismo
preprocesado que ml/preprocessing.py (mismas columnas y orden, mismos
encoders, mismo scaler, misma selección de características), pero flujo a
flujo en tiempo real en vez de en lote sobre el CSV, de modo que un flujo
se clasifica igual que se habría clasificado al entrenar.
 
Las 4 características de ventana temporal se calculan con el mismo módulo
compartido (feature_windows.WindowTracker) que el preprocesado, aquí
alimentado en cada sondeo. Carga los artefactos de ml/train.py:
best_model.pkl, scaler.pkl, selected_features.pkl, encoders.pkl y
le_y.pkl.
"""
import os
import time
import warnings

import numpy as np
import pandas as pd

# sklearn avisa en cada predicción de que el array no lleva nombres de
# columna. Es inofensivo (van en el orden correcto), pero repetido en
# cada flujo saturaría el log del controlador. Se silencia.
warnings.filterwarnings(
    "ignore",
    message="X does not have valid feature names",
    category=UserWarning,
)

# Añade la raíz del proyecto al path: al cargarse desde ryu-manager
# podría no estar, y 'config', 'feature_windows' y 'ml.utils' deben
# resolverse igual que en el resto del proyecto.
import sys
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import config
from feature_windows import WindowTracker
from ml.utils import load_artifact

# Ventana temporal de las características de patrón entre flujos. Se lee de
# config.py, que el preprocesado usa también: deben coincidir, porque da
# nombre a las columnas y define el cálculo.
_W = config.WINDOW_SECONDS

# Orden EXACTO de columnas tal y como las ve el modelo tras el
# preprocesado (ver ml/preprocessing.py). Debe coincidir una a una.
FEATURE_ORDER = [
    "eth_type", "ip_proto", "tcp_src_port", "tcp_dst_port",
    "udp_src_port", "udp_dst_port", "tcp_flags", "ip_mac_consistent",
    "arp_unsolicited_reply", "arp_opcode", "duration_sec", "duration_nsec",
    "packet_count", "byte_count", "packet_count_per_second",
    "byte_count_per_second", "avg_packet_size", "flow_count_per_dpid",
    f"distinct_ports_by_src_{_W}s", f"distinct_targets_by_src_{_W}s",
    f"flows_to_target_{_W}s", f"distinct_sources_to_target_{_W}s",
]

# Valor de relleno para huecos estructurales numéricos (mismo criterio
# que preprocessing.py: puertos/ARP que no aplican -> 0 tras el
# fillna(0) que hace el preprocesado sobre STRUCTURAL_NA_COLUMNS).
FILL = 0


class LiveClassifier:
    def __init__(self, model_name="best_model.pkl", window_s=None):
        self.window_s = window_s if window_s is not None else _W
        # best_model.pkl lo crea ml/evaluate.py; si aún no se ha evaluado,
        # se recurre a random_forest.pkl.
        try:
            self.model = load_artifact(model_name)
        except FileNotFoundError:
            self.model = load_artifact("random_forest.pkl")
        # Forzar n_jobs=1. El modelo se entrenó con n_jobs=-1 y ese valor
        # queda guardado en el .pkl, pero dentro del controlador Ryu
        # (eventlet con monkey-patching de threading) los workers paralelos
        # de joblib entran en deadlock y predict() se cuelga. Con n_jobs=1
        # no hay paralelismo ni deadlock, sin necesidad de reentrenar.
        try:
            self.model.n_jobs = 1
        except Exception:
            pass
        try:
            print(f"[live_classifier] modelo cargado ({type(self.model).__name__}), "
                  f"n_jobs={getattr(self.model, 'n_jobs', '?')}", flush=True)
        except Exception:
            pass
        self.scaler = load_artifact("scaler.pkl")
        self.selected_features = load_artifact("selected_features.pkl")
        # Índices de las features seleccionadas dentro de FEATURE_ORDER,
        # para poder cortar el vector escalado sin reconstruir un
        # DataFrame en cada flujo (optimización del tiempo de inferencia).
        self._selected_idx = [FEATURE_ORDER.index(f) for f in self.selected_features]
        self.encoders = load_artifact("encoders.pkl")
        self.le_y = load_artifact("le_y.pkl")
        # Tablas valor -> código para las categóricas, indexadas por el
        # valor NUMÉRICO (ver _encode_categorical para el porqué).
        self._cat_maps = {}
        for col, le in self.encoders.items():
            m = {}
            for i, c in enumerate(le.classes_):
                try:
                    m[float(c)] = i
                except (TypeError, ValueError):
                    pass
            self._cat_maps[col] = m

        # WindowTrackers en vivo (mismos que preprocessing.py, ver allí
        # el porqué de cada clave/valor).
        self._src_port = WindowTracker(self.window_s)   # origen -> puerto dst
        self._src_dst = WindowTracker(self.window_s)    # origen -> destino
        self._dst_src = WindowTracker(self.window_s)    # (destino,puerto) -> origen
        self._last_ports_by_src = {}
        self._last_window = {"distinct_ports": 0, "distinct_targets": 0,
                             "flows_to_target": 0, "distinct_sources": 0}

    # -- codificación de categóricas igual que en el preprocesado -------
    def _encode_categorical(self, col, value):
        """Aplica la misma codificación que el LabelEncoder del preprocesado,
        comparando por valor numérico.
 
        Es imprescindible comparar por número, no por texto: en el CSV las
        categóricas tienen huecos, así que pandas las leyó como float y el
        encoder aprendió las clases como "6.0", "1.0"... En vivo llegan
        como enteros, y str(6)="6" no casaría con "6.0", codificándolo todo
        como la clase 0. Los huecos y las categorías nunca vistas se tratan
        como 0.0 ("no aplica"), igual que el fillna(0) del preprocesado."""
        m = self._cat_maps.get(col)
        if m is None:
            return _num(value)
        try:
            v = 0.0 if value in (None, "") else float(value)
        except (TypeError, ValueError):
            v = 0.0
        if v in m:
            return m[v]
        return m.get(0.0, 0)

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

        # Identificadores de las ventanas, con el mismo criterio que
        # preprocessing.py: origen = ip_src o, si es ARP, la MAC origen
        # (eth_src, no arp_spa); destino = ip_dst o arp_tpa. Deben coincidir
        # con el entrenamiento o las 4 características se calcularían sobre
        # claves distintas.
        src_id = raw.get("ip_src") or raw.get("eth_src") or "?"
        dst_id = raw.get("ip_dst") or raw.get("arp_tpa") or "?"
        dst_port = raw.get("tcp_dst_port")
        if dst_port is None:
            dst_port = raw.get("udp_dst_port")
        dst_port = int(dst_port) if dst_port not in (None, "") else -1

        dports, dtargets, f2t, dsources = self._window_features(
            src_id, dst_id, dst_port, now
        )
        # Guardar las features de ventana recién calculadas para que
        # predict() pueda exponerlas (las usan las gráficas: p.ej.
        # distinct_ports en la de scanning, distinct_sources en la de ddos).
        self._last_window = {
            "distinct_ports": dports,
            "distinct_targets": dtargets,
            "flows_to_target": f2t,
            "distinct_sources": dsources,
        }

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
            f"distinct_ports_by_src_{_W}s": dports,
            f"distinct_targets_by_src_{_W}s": dtargets,
            f"flows_to_target_{_W}s": f2t,
            f"distinct_sources_to_target_{_W}s": dsources,
        }
        # Vector completo en el orden del entrenamiento, escalado.
        vec = np.array([[row[c] for c in FEATURE_ORDER]], dtype=float)
        scaled = self.scaler.transform(vec)  # devuelve ndarray
        # Quedarse solo con las columnas seleccionadas (por índice, sin
        # reconstruir un DataFrame -mucho más rápido por flujo-).
        return scaled[:, self._selected_idx]

    def predict(self, raw, now=None):
        """Clasifica un flujo. Devuelve (nombre_clase, tiempo_inferencia_ms,
        window_feats) donde window_feats es un dict con las features de
        ventana calculadas (para registrarlas en las métricas/gráficas)."""
        X = self.build_feature_row(raw, now)
        t0 = time.perf_counter()
        pred = self.model.predict(X)[0]
        infer_ms = (time.perf_counter() - t0) * 1000.0
        label = self.le_y.inverse_transform([pred])[0]
        return label, infer_ms, dict(self._last_window)

    def predict_batch(self, raws, now=None):
        """Clasifica varios flujos en una sola llamada al modelo.
 
        Es lo que evita que el controlador se atasque: llamar a predict()
        por flujo tiene un coste fijo por llamada que, multiplicado por
        todos los flujos de cada sondeo, deja al controlador atrás. Una
        sola llamada sobre la matriz completa los clasifica en unos pocos
        milisegundos. Las características de ventana sí se calculan flujo a
        flujo y en orden (el WindowTracker necesita secuencia), pero eso es
        barato. Devuelve (label, infer_ms_por_flujo, window_feats) por
        flujo, en el orden de 'raws'.
        """
        if not raws:
            return []
        rows, windows = [], []
        for raw in raws:
            # build_feature_row alimenta los WindowTracker y devuelve el
            # vector ya escalado y recortado a las features seleccionadas.
            rows.append(self.build_feature_row(raw, now)[0])
            windows.append(dict(self._last_window))
        X = np.vstack(rows)
        t0 = time.perf_counter()
        preds = self.model.predict(X)
        total_ms = (time.perf_counter() - t0) * 1000.0
        labels = self.le_y.inverse_transform(preds)
        # Tiempo de inferencia repartido por flujo (para las métricas).
        per_flow_ms = total_ms / len(raws)
        return [(labels[i], per_flow_ms, windows[i]) for i in range(len(raws))]


def _num(v):
    """Convierte a número; huecos/vacíos -> FILL (0), igual que el
    fillna(0) del preprocesado sobre columnas de NaN estructural."""
    if v is None or v == "":
        return FILL
    try:
        return float(v)
    except (TypeError, ValueError):
        return FILL
