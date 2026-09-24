"""
defense/plots.py
----------------
Genera las gráficas y tablas de la fase de detección y mitigación a
partir del CSV de eventos que escribe controller/sdn_defense.py
(results/events/defense_events.csv).

Cada gráfica de tráfico usa la columna 'traffic_phase' (qué prueba
estaba en marcha), NO 'predicted_label' -así la gráfica de "scanning"
muestra TODO lo ocurrido durante la prueba de scanning (incluidos los
flujos que el modelo no acertó), que es lo que interesa para ver el
comportamiento de la red durante ese ataque-.

Todas las gráficas marcan con una línea vertical los instantes en que se
aplicó una regla DROP (mitigación).

Si el CSV trae la columna 'true_label' (etiqueta REAL de cada flujo,
calculada por el controlador con el mismo criterio que el dataset), se
generan además la matriz de confusión de la fase en vivo y una tabla de
precision/recall por clase -directamente comparables con las de la
validación GroupKFold de la fase 2-.

Nota de compatibilidad: se pasan siempre numpy arrays a matplotlib
(nunca Series de pandas), porque algunas versiones fallan al indexar
una Series dentro de ax.plot().
"""
import os
import sys

# Permite ejecutarlo directamente (python3 defense/plots.py) sin depender
# de la instalación editable: añade la raíz del proyecto al path.
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ROOT not in sys.path:
    sys.path.insert(0, _ROOT)

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import config

EVENTS_DIR = os.path.join(config.PROJECT_ROOT, "results", "events")
FIGURES_DIR = os.path.join(config.PROJECT_ROOT, "results", "figures", "defense")
TABLES_DIR = os.path.join(config.PROJECT_ROOT, "results", "tables")
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs(TABLES_DIR, exist_ok=True)


def _load(events_csv):
    df = pd.read_csv(events_csv)
    df["t"] = pd.to_datetime(df["timestamp"])
    df["t_rel"] = (df["t"] - df["t"].min()).dt.total_seconds()
    # Compatibilidad con CSV antiguos sin las columnas traffic_phase / run.
    if "traffic_phase" not in df.columns:
        df["traffic_phase"] = df["predicted_label"]
    if "run" not in df.columns:
        df["run"] = 1
    return df


def _arr(series):
    return pd.to_numeric(series, errors="coerce").to_numpy()


def representative_run(df):
    """Ejecución REPRESENTATIVA de la batería: aquella cuyo F1 macro está
    más cerca de la media de todas. Las gráficas temporales muestran una
    sola ejecución (promediar curvas de ejecuciones distintas no tiene
    sentido: cada una tiene su ritmo, sus instantes de DROP y su nº de
    flujos), y conviene que sea un caso típico y no el mejor ni el peor
    -que es lo que pasaba antes usando simplemente la última-.
    Si no se puede calcular (una sola ejecución, o ejecuciones
    incompletas), devuelve la última."""
    runs = sorted(df["run"].unique())
    if len(runs) < 2 or "true_label" not in df.columns:
        return runs[-1] if runs else None
    try:
        from sklearn.metrics import f1_score
        f1s = {}
        for run in runs:
            g = df[df["run"] == run]
            if set(CLASSES) <= set(g["traffic_phase"]):
                f1s[run] = f1_score(g["true_label"], g["predicted_label"],
                                    labels=CLASSES, average="macro", zero_division=0)
        if not f1s:
            return runs[-1]
        media = sum(f1s.values()) / len(f1s)
        return min(f1s, key=lambda r: abs(f1s[r] - media))
    except Exception:
        return runs[-1]


def _phase(df, phase, one_run=False):
    """Filas de una prueba concreta (por traffic_phase), con el tiempo
    (t_rel) medido desde el INICIO DE ESA PRUEBA. Así, en la batería,
    cada gráfica empieza en 0 s en vez de en el segundo de la batería en
    que arrancó esa prueba.

    one_run=True: solo la ejecución representativa de la batería (ver
    representative_run). Lo usan las gráficas temporales; las tablas y la
    matriz de confusión usan todas las ejecuciones."""
    d = df[df["traffic_phase"] == phase]
    if one_run and len(d):
        d = d[d["run"] == representative_run(df)]
    d = d.copy()
    if len(d):
        d["t_rel"] = (d["t"] - d["t"].min()).dt.total_seconds()
    return d


def _mark_drops(ax, d):
    """Marca con líneas verticales los DROP DENTRO de la prueba mostrada."""
    drops = d[d["mitigated"] == 1]
    for i, t in enumerate(drops["t_rel"].to_numpy()):
        ax.axvline(t, color="red", linestyle="--", alpha=0.35,
                   label="Regla DROP aplicada" if i == 0 else None)


def _break_gaps(x, y, max_gap=2.0):
    """Inserta un NaN donde pasan más de max_gap segundos sin eventos, para
    que la línea se corte en vez de unir los dos lados con una recta que
    aparenta tráfico donde no lo hubo (p.ej. mientras un DROP bloquea el
    ataque, no llega ningún flujo)."""
    if len(x) < 2:
        return x, y
    xs, ys = [x[0]], [y[0]]
    for i in range(1, len(x)):
        if x[i] - x[i - 1] > max_gap:
            xs.append(np.nan); ys.append(np.nan)
        xs.append(x[i]); ys.append(y[i])
    return np.array(xs, dtype=float), np.array(ys, dtype=float)


def _run_suffix(df):
    """Sufijo para el título si la batería tiene varias ejecuciones."""
    n = df["run"].nunique()
    if n < 2:
        return ""
    return f" (ejecución representativa: {representative_run(df)} de {n})"


def _timeline_plot(df, phase, ycol, ylabel, title, color, out_name, logy=False):
    d = _phase(df, phase, one_run=True)
    title = title + _run_suffix(df)
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        x, y = _break_gaps(d["t_rel"].to_numpy(), _arr(d[ycol]))
        ax.plot(x, y, marker=".", linestyle="-", color=color, label=ylabel)
        _mark_drops(ax, d)
        ax.legend()
    else:
        ax.text(0.5, 0.5, f"(sin datos de la prueba '{phase}')",
                ha="center", va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel(ylabel + (" - escala log" if logy else ""))
    if logy:
        # "symlog" y no "log": admite los ceros (flujos sin tráfico en ese
        # sondeo), que en escala log pura desaparecerían.
        ax.set_yscale("symlog", linthresh=1)
        ax.set_ylim(bottom=0)   # una tasa nunca es negativa
    ax.set_title(title)
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, out_name)
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_ddos(events_csv):
    """DDoS: tasa de paquetes/s durante la prueba de ddos.

    Eje Y en escala logarítmica: la tasa de un flujo recién instalado se
    estima como paquetes / edad del flujo (mismo cálculo que el monitor
    del dataset), y con edades de milisegundos salen picos de cientos de
    miles de pkt/s que, en escala lineal, aplastan el resto de la gráfica
    y ocultan la tasa real del ataque (~500-1000 pkt/s por atacante)."""
    return _timeline_plot(_load(events_csv), "ddos", "pkt_rate",
                          "Tasa de paquetes (pkt/s)",
                          "DDoS (hping3): tasa de paquetes/s y momentos de mitigación",
                          "#c0392b", "ddos_pkt_rate.png", logy=True)


def plot_scanning(events_csv):
    """Scanning: nº de flujos de escaneo acumulados durante la prueba.

    Se usa el acumulado de flujos (no 'puertos únicos'): con el sondeo
    cada 1s cada flujo se ve por separado con 1 puerto, así que 'puertos
    únicos' salía siempre 1 y la gráfica era una línea plana. El nº de
    flujos acumulados refleja mejor la actividad de escaneo (un escaneo
    toca muchos destinos/puertos -> muchos flujos)."""
    df = _load(events_csv)
    d = _phase(df, "scanning", one_run=True)
    # Solo los flujos que SON escaneo (etiqueta real), no el tráfico de
    # fondo ni el warmup ARP previo. Las líneas DROP se siguen marcando
    # sobre toda la prueba.
    d_all = d
    if "true_label" in d.columns:
        d = d[d["true_label"] == "scanning"]
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        acum = np.arange(1, len(d) + 1)
        ax.plot(d["t_rel"].to_numpy(), acum, marker=".", linestyle="-",
                color="#e67e22", label="flujos de escaneo acumulados")
        _mark_drops(ax, d_all)
        ax.legend()
    else:
        ax.text(0.5, 0.5, "(sin datos de la prueba 'scanning')", ha="center",
                va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Flujos de escaneo detectados (acumulado)")
    ax.set_title("Scanning (nmap): actividad de escaneo y momentos de mitigación"
                 + _run_suffix(df))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "scanning_ports.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_spoofing(events_csv):
    """Spoofing: detecciones acumuladas durante la prueba de spoofing."""
    df = _load(events_csv)
    d = _phase(df, "spoofing", one_run=True)
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        # nº de flujos clasificados como spoofing, acumulado en el tiempo
        is_spoof = (d["predicted_label"] == "spoofing").astype(int).to_numpy()
        ax.plot(d["t_rel"].to_numpy(), np.cumsum(is_spoof), marker=".",
                linestyle="-", color="#8e44ad",
                label="detecciones de spoofing acumuladas")
        _mark_drops(ax, d)
        ax.legend()
    else:
        ax.text(0.5, 0.5, "(sin datos de la prueba 'spoofing')",
                ha="center", va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Flujos de spoofing detectados (acumulado)")
    ax.set_title("Spoofing (ARP/IP): detecciones y momentos de mitigación"
                 + _run_suffix(df))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "spoofing_detected.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_normal(events_csv):
    """Tráfico normal: tasa de paquetes durante la prueba normal
    (idealmente sin DROP: sirve para ver los falsos positivos)."""
    return _timeline_plot(_load(events_csv), "normal", "pkt_rate",
                          "Tasa de paquetes (pkt/s)",
                          "Tráfico normal: tasa de paquetes (idealmente sin DROP)",
                          "#27ae60", "normal_pkt_rate.png")


def plot_cpu_latency(events_csv):
    """Gráfica de doble eje CPU de Ryu (Y1) vs latencia del plano de
    control (Y2) a lo largo del tiempo, con una SUBGRÁFICA por cada tipo
    de tráfico (normal/scanning/ddos/spoofing) -así se ve el impacto de
    cada uno por separado, además de la tabla-."""
    df = _load(events_csv)
    phases = ["normal", "scanning", "ddos", "spoofing"]
    fig, axes = plt.subplots(2, 2, figsize=(14, 9))
    for ax1, phase in zip(axes.flat, phases):
        d = _phase(df, phase, one_run=True)
        if not len(d):
            ax1.text(0.5, 0.5, f"(sin datos de '{phase}')", ha="center",
                     va="center", transform=ax1.transAxes, color="gray")
            ax1.set_title(phase)
            continue
        # reloj relativo al inicio de ESA fase
        tr = (d["t"] - d["t"].min()).dt.total_seconds().to_numpy()
        x_cpu, y_cpu = _break_gaps(tr, _arr(d["ryu_cpu_percent"]))
        ax1.plot(x_cpu, y_cpu, color="#2980b9", label="CPU Ryu (%)")
        ax1.set_ylabel("CPU Ryu (%)", color="#2980b9")
        ax1.tick_params(axis="y", labelcolor="#2980b9")
        ax1.set_xlabel("Tiempo (s)")
        ax2 = ax1.twinx()
        lat_mask = pd.to_numeric(d["control_latency_ms"], errors="coerce").notna().to_numpy()
        if lat_mask.any():
            ax2.scatter(tr[lat_mask], _arr(d["control_latency_ms"])[lat_mask],
                        color="#c0392b", s=18, label="Latencia control (ms)")
        ax2.set_ylabel("Latencia control (ms)", color="#c0392b")
        ax2.tick_params(axis="y", labelcolor="#c0392b")
        ax1.set_title(phase)
    fig.suptitle("Impacto en infraestructura por tipo de tráfico: "
                 "CPU de Ryu vs latencia del plano de control" + _run_suffix(df))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "cpu_vs_latency.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


CLASSES = ["normal", "scanning", "ddos", "spoofing"]


def plot_confusion_live(events_csv):
    """Matriz de confusión de la fase EN VIVO (etiqueta real vs
    predicción), sobre todos los flujos clasificados (todas las
    ejecuciones de la batería)."""
    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None
    from sklearn.metrics import confusion_matrix, ConfusionMatrixDisplay
    labels = [c for c in CLASSES
              if c in set(df["true_label"]) | set(df["predicted_label"])]
    cm = confusion_matrix(df["true_label"], df["predicted_label"], labels=labels)
    fig, ax = plt.subplots(figsize=(6, 5))
    ConfusionMatrixDisplay(cm, display_labels=labels).plot(
        ax=ax, cmap="Blues", colorbar=False, xticks_rotation=45)
    n = df["run"].nunique()
    ax.set_title("Matriz de confusión - detección en vivo"
                 + (f" ({n} ejecuciones)" if n > 1 else ""))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "confusion_matrix_live.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def table_infrastructure(events_csv):
    """TABLA del impacto en infraestructura POR TIPO DE TRÁFICO, en tabla
    y no en gráfica porque así se leen los valores exactos por clase, que
    en una nube de puntos no se distinguen:

      - CPU media y máxima del proceso Ryu.
      - Latencia del plano de control: del evento OFPFlowStatsReply al
        envío de la regla OFPFlowMod (solo se mide cuando hay mitigación).
      - Tiempo de inferencia del modelo por flujo (media, máximo y
        desviación). Es el coste amortizado: el controlador clasifica de
        una vez todos los flujos de un sondeo, así que el coste fijo de
        cada llamada al modelo se reparte entre los flujos del lote.
      - Nº de mitigaciones aplicadas.

    Antes esto estaba repartido en dos tablas (CPU/latencia e inferencia)
    que repetían la columna de inferencia media; es la misma medida sobre
    los mismos eventos, así que va en una sola."""
    df = _load(events_csv)
    rows = []
    for phase in CLASSES:
        d = _phase(df, phase)
        if not len(d):
            continue
        cpu = pd.to_numeric(d["ryu_cpu_percent"], errors="coerce").dropna()
        lat = pd.to_numeric(d["control_latency_ms"], errors="coerce").dropna()
        inf = pd.to_numeric(d["inference_ms"], errors="coerce").dropna()

        def r(serie, fn, n=2):
            return round(fn(serie), n) if len(serie) else ""
        rows.append({
            "traffic_phase": phase,
            "events": len(d),
            "ryu_cpu_mean_pct": r(cpu, lambda x: x.mean()),
            "ryu_cpu_max_pct": r(cpu, lambda x: x.max()),
            "control_latency_mean_ms": r(lat, lambda x: x.mean()),
            "control_latency_max_ms": r(lat, lambda x: x.max()),
            "inference_mean_ms": r(inf, lambda x: x.mean(), 3),
            "inference_max_ms": r(inf, lambda x: x.max(), 3),
            "inference_std_ms": r(inf, lambda x: x.std(), 3),
            "mitigations": int((d["mitigated"] == 1).sum()),
        })
    tabla = pd.DataFrame(rows)
    out = os.path.join(TABLES_DIR, "defense_infrastructure_by_traffic.csv")
    tabla.to_csv(out, index=False)
    return out, tabla


def _prf(df, labels):
    """precision/recall/F1/soporte por clase (sklearn), como dicts."""
    from sklearn.metrics import precision_recall_fscore_support
    p, r, f, n = precision_recall_fscore_support(
        df["true_label"], df["predicted_label"], labels=labels, zero_division=0)
    return {c: (p[i], r[i], f[i], int(n[i])) for i, c in enumerate(labels)}


def table_detection(events_csv):
    """TABLA principal de resultados de la fase 3: precision / recall / F1
    por clase y su media macro (fila macro_avg), sobre todos los flujos
    clasificados y con el mismo criterio de etiqueta que la evaluación
    offline de la fase 2 -por eso su F1 macro es el comparable con el de
    la fase 2-. Si la batería se repitió, se suman todas las ejecuciones
    (la variación entre ejecuciones está en table_battery_runs).

    Además, por clase de ataque: tiempo hasta la primera mitigación (media
    entre ejecuciones; desde el primer flujo del ataque visto por el
    controlador hasta el primer DROP correcto) y nº de DROP.
    Solo tiene sentido con la BATERÍA (las 4 clases en el mismo CSV); en
    una prueba individual no hay con qué confundir."""
    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None, None
    labels = [c for c in CLASSES if c in set(df["true_label"])]
    m = _prf(df, labels)
    rows = []
    for c in labels:
        d = df[df["true_label"] == c]
        t_mit = ""
        if c != "normal":
            tiempos = []
            for _, g in d.groupby("run"):
                mit = g[g["mitigated"] == 1]
                if len(mit):
                    tiempos.append((mit["t"].min() - g["t"].min()).total_seconds())
            if tiempos:
                t_mit = round(float(np.mean(tiempos)), 2)
        p, r, f, n = m[c]
        rows.append({
            "class": c, "flows": n,
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
            "first_mitigation_s": t_mit,
            "drops": int((d["mitigated"] == 1).sum()),
        })
    tabla = pd.DataFrame(rows)
    if len(tabla) > 1:
        macro = {"class": "macro_avg", "flows": int(tabla["flows"].sum()),
                 "first_mitigation_s": "", "drops": int(tabla["drops"].sum())}
        for col in ["precision", "recall", "f1"]:
            macro[col] = round(tabla[col].mean(), 3)
        tabla = pd.concat([tabla, pd.DataFrame([macro])], ignore_index=True)
    out = os.path.join(TABLES_DIR, "defense_detection_by_class.csv")
    tabla.to_csv(out, index=False)
    return out, tabla


def table_battery_runs(events_csv):
    """TABLA de métricas macro POR EJECUCIÓN de la batería, más su media y
    desviación típica. Es el equivalente en vivo de la media ± desviación
    entre particiones de GroupKFold de la fase 2: cada batería elige al
    azar atacantes, víctimas y variantes, así que una sola ejecución es
    una única muestra. Solo se genera si hay varias ejecuciones."""
    df = _load(events_csv)
    if "true_label" not in df.columns or df["run"].nunique() < 2:
        return None, None
    from sklearn.metrics import precision_score, recall_score, f1_score
    rows = []
    kw = dict(labels=CLASSES, average="macro", zero_division=0)
    for run, g in df.groupby("run"):
        if not set(CLASSES) <= set(g["traffic_phase"]):
            continue   # ejecución incompleta (p.ej. interrumpida)
        rows.append({
            "run": str(run), "flows": len(g),
            "precision_macro": precision_score(g["true_label"], g["predicted_label"], **kw),
            "recall_macro": recall_score(g["true_label"], g["predicted_label"], **kw),
            "f1_macro": f1_score(g["true_label"], g["predicted_label"], **kw),
        })
    if len(rows) < 2:
        return None, None
    tabla = pd.DataFrame(rows)
    cols = ["precision_macro", "recall_macro", "f1_macro"]
    # Media y desviación típica (poblacional, igual que np.std en la fase
    # 2) sobre los valores SIN redondear; se redondea solo al final.
    media = {"run": "mean", "flows": round(tabla["flows"].mean(), 1)}
    std = {"run": "std", "flows": round(tabla["flows"].std(ddof=0), 1)}
    for c in cols:
        media[c] = tabla[c].mean()
        std[c] = tabla[c].std(ddof=0)
    tabla["flows"] = tabla["flows"].astype(object)
    tabla = pd.concat([tabla, pd.DataFrame([media, std])], ignore_index=True)
    tabla[cols] = tabla[cols].astype(float).round(3)
    out = os.path.join(TABLES_DIR, "defense_battery_runs.csv")
    tabla.to_csv(out, index=False)
    return out, tabla


def generate_one(kind, events_csv=None):
    """Genera SOLO la gráfica del tipo de tráfico indicado (para las
    pruebas individuales). No genera las de otros tipos ni las tablas."""
    events_csv = events_csv or os.path.join(EVENTS_DIR, "defense_events.csv")
    if not os.path.exists(events_csv):
        print(f"[plots] No existe {events_csv}; ejecuta antes una prueba.")
        return None
    fn = {
        "normal": plot_normal,
        "scanning": plot_scanning,
        "ddos": plot_ddos,
        "spoofing": plot_spoofing,
    }.get(kind)
    if fn is None:
        return None
    out = fn(events_csv)
    print(f"[plots] Gráfica generada: {out}")
    return out


def generate_all(events_csv=None):
    """Genera todas las gráficas y tablas. Devuelve la lista de rutas."""
    events_csv = events_csv or os.path.join(EVENTS_DIR, "defense_events.csv")
    if not os.path.exists(events_csv):
        print(f"[plots] No existe {events_csv}; ejecuta antes una prueba de tráfico.")
        return []
    outs = [
        plot_ddos(events_csv), plot_scanning(events_csv),
        plot_spoofing(events_csv), plot_normal(events_csv),
        plot_cpu_latency(events_csv),
    ]
    cm_out = plot_confusion_live(events_csv)
    if cm_out:
        outs.append(cm_out)
    n_figs = len(outs)
    infra_out, infra_tab = table_infrastructure(events_csv)
    det_out, det_tab = table_detection(events_csv)
    runs_out, runs_tab = table_battery_runs(events_csv)
    outs.append(infra_out)

    print("[plots] Gráficas generadas:")
    for o in outs[:n_figs]:
        print("   ", o)
    print("[plots] Tablas generadas:")
    print("   ", infra_out)
    print(infra_tab.to_string(index=False))
    if det_out:
        outs.append(det_out)
        print("   ", det_out)
        print(det_tab.to_string(index=False))
    if runs_out:
        outs.append(runs_out)
        print("   ", runs_out)
        print(runs_tab.to_string(index=False))
    return outs


if __name__ == "__main__":
    # Regenera gráficas y tablas a partir de un CSV ya recogido, sin volver
    # a lanzar la red. Por defecto, el último (results/events/defense_events.csv):
    #     venv/bin/python3 defense/plots.py
    #     venv/bin/python3 defense/plots.py results/events/defense_events_battery.csv
    generate_all(sys.argv[1] if len(sys.argv) > 1 else None)
