"""
defense/plots.py
----------------
Genera las gráficas y tablas de la fase de detección y mitigación a
partir del CSV de eventos que escribe controller/sdn_defense.py
(results/metrics/defense_events.csv).

Cada gráfica de tráfico usa la columna 'traffic_phase' (qué prueba
estaba en marcha), NO 'predicted_label' -así la gráfica de "scanning"
muestra TODO lo ocurrido durante la prueba de scanning (incluidos los
flujos que el modelo no acertó), que es lo que interesa para ver el
comportamiento de la red durante ese ataque-.

Todas las gráficas marcan con una línea vertical los instantes en que se
aplicó una regla DROP (mitigación).

Nota de compatibilidad: se pasan siempre numpy arrays a matplotlib
(nunca Series de pandas), porque algunas versiones fallan al indexar
una Series dentro de ax.plot().
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd

import config

METRICS_DIR = os.path.join(config.PROJECT_ROOT, "results", "metrics")
FIGURES_DIR = os.path.join(config.PROJECT_ROOT, "results", "figures", "defense")
TABLES_DIR = os.path.join(config.PROJECT_ROOT, "results", "tables")
os.makedirs(FIGURES_DIR, exist_ok=True)
os.makedirs(TABLES_DIR, exist_ok=True)


def _load(events_csv):
    df = pd.read_csv(events_csv)
    df["t"] = pd.to_datetime(df["timestamp"])
    df["t_rel"] = (df["t"] - df["t"].min()).dt.total_seconds()
    # Compatibilidad con CSV antiguos sin la columna traffic_phase.
    if "traffic_phase" not in df.columns:
        df["traffic_phase"] = df["predicted_label"]
    return df


def _arr(series):
    return pd.to_numeric(series, errors="coerce").to_numpy()


def _phase(df, phase):
    """Filas de una prueba concreta (por traffic_phase)."""
    return df[df["traffic_phase"] == phase]


def _mark_drops(ax, d):
    """Marca con líneas verticales los DROP DENTRO de la prueba mostrada."""
    drops = d[d["mitigated"] == 1]
    for i, t in enumerate(drops["t_rel"].to_numpy()):
        ax.axvline(t, color="red", linestyle="--", alpha=0.35,
                   label="Regla DROP aplicada" if i == 0 else None)


def _timeline_plot(df, phase, ycol, ylabel, title, color, out_name):
    d = _phase(df, phase)
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        ax.plot(d["t_rel"].to_numpy(), _arr(d[ycol]),
                marker=".", linestyle="-", color=color, label=ylabel)
        _mark_drops(ax, d)
        ax.legend()
    else:
        ax.text(0.5, 0.5, f"(sin datos de la prueba '{phase}')",
                ha="center", va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel(ylabel)
    ax.set_title(title)
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, out_name)
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_ddos(events_csv):
    """DDoS: tasa de paquetes/s durante la prueba de ddos."""
    return _timeline_plot(_load(events_csv), "ddos", "pkt_rate",
                          "Tasa de paquetes (pkt/s)",
                          "DDoS (hping3): tasa de paquetes/s y momentos de mitigación",
                          "#c0392b", "ddos_pkt_rate.png")


def plot_scanning(events_csv):
    """Scanning: nº de flujos de escaneo acumulados durante la prueba.

    Se usa el acumulado de flujos (no 'puertos únicos'): con el sondeo
    cada 1s cada flujo se ve por separado con 1 puerto, así que 'puertos
    únicos' salía siempre 1 y la gráfica era una línea plana. El nº de
    flujos acumulados refleja mejor la actividad de escaneo (un escaneo
    toca muchos destinos/puertos -> muchos flujos)."""
    df = _load(events_csv)
    d = _phase(df, "scanning")
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        acum = np.arange(1, len(d) + 1)
        ax.plot(d["t_rel"].to_numpy(), acum, marker=".", linestyle="-",
                color="#e67e22", label="flujos de escaneo acumulados")
        _mark_drops(ax, d)
        ax.legend()
    else:
        ax.text(0.5, 0.5, "(sin datos de la prueba 'scanning')", ha="center",
                va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Flujos de escaneo detectados (acumulado)")
    ax.set_title("Scanning (nmap): actividad de escaneo y momentos de mitigación")
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "scanning_ports.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_spoofing(events_csv):
    """Spoofing: detecciones acumuladas durante la prueba de spoofing."""
    df = _load(events_csv)
    d = _phase(df, "spoofing")
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
    ax.set_title("Spoofing (ARP/IP): detecciones y momentos de mitigación")
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
        d = _phase(df, phase)
        if not len(d):
            ax1.text(0.5, 0.5, f"(sin datos de '{phase}')", ha="center",
                     va="center", transform=ax1.transAxes, color="gray")
            ax1.set_title(phase)
            continue
        # reloj relativo al inicio de ESA fase
        tr = (d["t"] - d["t"].min()).dt.total_seconds().to_numpy()
        ax1.plot(tr, _arr(d["ryu_cpu_percent"]), color="#2980b9",
                 label="CPU Ryu (%)")
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
                 "CPU de Ryu vs latencia del plano de control")
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "cpu_vs_latency.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def table_cpu_latency(events_csv):
    """TABLA (no gráfica) del impacto en infraestructura POR TIPO DE
    TRÁFICO: CPU media del proceso Ryu y latencia del plano de control
    (evento OFPFlowStatsReply -> envío de la regla OFPFlowMod). En tabla
    porque, como pediste, así se leen los valores exactos por clase, que
    en una gráfica de puntos no se distinguen bien."""
    df = _load(events_csv)
    rows = []
    for phase in ["normal", "scanning", "ddos", "spoofing"]:
        d = _phase(df, phase)
        if not len(d):
            continue
        cpu = pd.to_numeric(d["ryu_cpu_percent"], errors="coerce")
        lat = pd.to_numeric(d["control_latency_ms"], errors="coerce").dropna()
        inf = pd.to_numeric(d["inference_ms"], errors="coerce")
        rows.append({
            "traffic_phase": phase,
            "eventos": len(d),
            "cpu_ryu_media_%": round(cpu.mean(), 2) if len(cpu) else "",
            "cpu_ryu_max_%": round(cpu.max(), 2) if len(cpu) else "",
            "latencia_control_media_ms": round(lat.mean(), 2) if len(lat) else "",
            "latencia_control_max_ms": round(lat.max(), 2) if len(lat) else "",
            "n_mitigaciones": int((d["mitigated"] == 1).sum()),
            "inferencia_media_ms": round(inf.mean(), 3) if len(inf) else "",
        })
    tabla = pd.DataFrame(rows)
    out = os.path.join(TABLES_DIR, "defense_cpu_latency_por_trafico.csv")
    tabla.to_csv(out, index=False)
    return out, tabla


def table_inference(events_csv):
    """TABLA del tiempo de inferencia del modelo por tipo de tráfico."""
    df = _load(events_csv)
    rows = []
    for phase in ["normal", "scanning", "ddos", "spoofing"]:
        d = _phase(df, phase)
        if not len(d):
            continue
        inf = pd.to_numeric(d["inference_ms"], errors="coerce").dropna()
        if not len(inf):
            continue
        rows.append({
            "traffic_phase": phase,
            "inferencia_media_ms": round(inf.mean(), 3),
            "inferencia_min_ms": round(inf.min(), 3),
            "inferencia_max_ms": round(inf.max(), 3),
            "inferencia_std_ms": round(inf.std(), 3),
        })
    tabla = pd.DataFrame(rows)
    out = os.path.join(TABLES_DIR, "defense_inferencia_por_trafico.csv")
    tabla.to_csv(out, index=False)
    return out, tabla


def generate_one(kind, events_csv=None):
    """Genera SOLO la gráfica del tipo de tráfico indicado (para las
    pruebas individuales). No genera las de otros tipos ni las tablas."""
    events_csv = events_csv or os.path.join(METRICS_DIR, "defense_events.csv")
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
    events_csv = events_csv or os.path.join(METRICS_DIR, "defense_events.csv")
    if not os.path.exists(events_csv):
        print(f"[plots] No existe {events_csv}; ejecuta antes una prueba de tráfico.")
        return []
    outs = [
        plot_ddos(events_csv), plot_scanning(events_csv),
        plot_spoofing(events_csv), plot_normal(events_csv),
        plot_cpu_latency(events_csv),
    ]
    cpu_out, cpu_tab = table_cpu_latency(events_csv)
    inf_out, inf_tab = table_inference(events_csv)
    outs += [cpu_out, inf_out]

    print("[plots] Gráficas generadas:")
    for o in outs[:5]:
        print("   ", o)
    print("[plots] Tablas generadas:")
    print("   ", cpu_out)
    print(cpu_tab.to_string(index=False))
    print("   ", inf_out)
    print(inf_tab.to_string(index=False))
    return outs


if __name__ == "__main__":
    generate_all()
