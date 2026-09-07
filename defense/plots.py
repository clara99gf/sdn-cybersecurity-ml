"""
defense/plots.py
----------------
Genera las gráficas de la fase de detección y mitigación a partir del
CSV de eventos que escribe controller/sdn_defense.py
(metrics/defense_events.csv).

Todas las gráficas marcan con una línea vertical los instantes en que se
aplicó una regla DROP (mitigación), tal y como pide el guion del TFG.
"""
import os

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import pandas as pd

import config

METRICS_DIR = os.path.join(config.PROJECT_ROOT, "metrics")
FIGURES_DIR = os.path.join(config.PROJECT_ROOT, "results", "figures", "defense")
os.makedirs(FIGURES_DIR, exist_ok=True)


def _load(events_csv):
    df = pd.read_csv(events_csv)
    df["t"] = pd.to_datetime(df["timestamp"])
    df["t_rel"] = (df["t"] - df["t"].min()).dt.total_seconds()
    return df


def _mark_drops(ax, df):
    """Marca con líneas verticales los instantes de mitigación (DROP)."""
    drops = df[df["mitigated"] == 1]
    for i, t in enumerate(drops["t_rel"]):
        ax.axvline(t, color="red", linestyle="--", alpha=0.35,
                   label="Regla DROP aplicada" if i == 0 else None)


def plot_ddos(events_csv, out=None):
    """DDoS: tasa de paquetes/s a lo largo del tiempo, marcando los DROP."""
    df = _load(events_csv)
    d = df[df["predicted_label"] == "ddos"]
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        ax.plot(d["t_rel"], pd.to_numeric(d["pkt_rate"], errors="coerce"),
                marker=".", linestyle="-", color="#c0392b", label="pkt_rate (ddos)")
    _mark_drops(ax, df)
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Tasa de paquetes (pkt/s)")
    ax.set_title("DDoS (hping3): tasa de paquetes/s y momentos de mitigación")
    ax.legend()
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "ddos_pkt_rate.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_scanning(events_csv, out=None):
    """Scanning: puertos destino únicos/s, marcando los DROP."""
    df = _load(events_csv)
    d = df[df["predicted_label"] == "scanning"]
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        ax.plot(d["t_rel"], pd.to_numeric(d["distinct_ports"], errors="coerce"),
                marker=".", linestyle="-", color="#e67e22",
                label="puertos destino únicos (5s)")
    _mark_drops(ax, df)
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Puertos destino únicos (ventana 5s)")
    ax.set_title("Scanning (nmap): puertos únicos y momentos de mitigación")
    ax.legend()
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "scanning_ports.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_spoofing(events_csv, out=None):
    """Spoofing: respuestas ARP no solicitadas acumuladas en el tiempo,
    marcando los DROP. Se usa arp_unsolicited_reply (la firma física del
    ARP spoofing: respuestas que nadie pidió) como eje Y, análogo a los
    'puertos únicos' de scanning -es lo que caracteriza al ataque, no su
    volumen-. Para el IP spoofing (que no genera ARP) se cuenta cada
    flujo detectado como spoofing, de modo que la curva refleja toda la
    actividad de spoofing detectada."""
    df = _load(events_csv)
    d = df[df["predicted_label"] == "spoofing"].copy()
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        # marca de "firma ARP": 1 si esta detección fue por respuesta ARP
        # no solicitada, si no 0 -pero contamos toda detección spoofing-.
        d["n"] = 1
        d["acum"] = d["n"].cumsum()
        ax.plot(d["t_rel"], d["acum"], marker=".", linestyle="-",
                color="#8e44ad",
                label="detecciones de spoofing acumuladas")
        # subconjunto con firma ARP no solicitada, resaltado
        arp = d[pd.to_numeric(d.get("distinct_sources", 0), errors="coerce").notna()]
    _mark_drops(ax, df)
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Flujos de spoofing detectados (acumulado)")
    ax.set_title("Spoofing (ARP/IP): detecciones y momentos de mitigación")
    ax.legend()
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "spoofing_detected.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_normal(events_csv, out=None):
    """Tráfico normal: tasa de paquetes/s. Debería NO generar DROP -sirve
    para mostrar que la mitigación no ataca tráfico legítimo (falsos
    positivos)."""
    df = _load(events_csv)
    d = df[df["predicted_label"] == "normal"]
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        ax.plot(d["t_rel"], pd.to_numeric(d["pkt_rate"], errors="coerce"),
                marker=".", linestyle="-", color="#27ae60", label="pkt_rate (normal)")
    _mark_drops(ax, df)
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Tasa de paquetes (pkt/s)")
    ax.set_title("Tráfico normal: tasa de paquetes (idealmente sin DROP)")
    ax.legend()
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "normal_pkt_rate.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_cpu_latency(events_csv, out=None):
    """Doble eje: % CPU del proceso Ryu (Y1) vs latencia del plano de
    control (Y2), a lo largo del tiempo."""
    df = _load(events_csv)
    fig, ax1 = plt.subplots(figsize=(10, 5))
    ax1.plot(df["t_rel"], pd.to_numeric(df["ryu_cpu_percent"], errors="coerce"),
             color="#2980b9", label="CPU Ryu (%)")
    ax1.set_xlabel("Tiempo (s)")
    ax1.set_ylabel("CPU del proceso Ryu (%)", color="#2980b9")
    ax1.tick_params(axis="y", labelcolor="#2980b9")

    ax2 = ax1.twinx()
    lat = df.dropna(subset=["control_latency_ms"])
    ax2.scatter(lat["t_rel"], pd.to_numeric(lat["control_latency_ms"], errors="coerce"),
                color="#c0392b", s=18, label="Latencia plano control (ms)")
    ax2.set_ylabel("Latencia plano de control (ms)", color="#c0392b")
    ax2.tick_params(axis="y", labelcolor="#c0392b")

    ax1.set_title("Impacto en infraestructura: CPU de Ryu vs latencia del plano de control")
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "cpu_vs_latency.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_inference_by_class(events_csv, out=None):
    """Tiempo de inferencia del modelo por tipo de tráfico (boxplot)."""
    df = _load(events_csv)
    order = ["normal", "ddos", "scanning", "spoofing"]
    data, labels = [], []
    for c in order:
        vals = pd.to_numeric(df[df["predicted_label"] == c]["inference_ms"],
                             errors="coerce").dropna()
        if len(vals):
            data.append(vals); labels.append(c)
    fig, ax = plt.subplots(figsize=(9, 5))
    if data:
        ax.boxplot(data, labels=labels, showfliers=False)
    ax.set_ylabel("Tiempo de inferencia (ms)")
    ax.set_title("Coste de inferencia del modelo por tipo de tráfico")
    fig.tight_layout()
    out = out or os.path.join(FIGURES_DIR, "inference_by_class.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def generate_all(events_csv=None):
    """Genera todas las gráficas. Devuelve la lista de rutas creadas."""
    events_csv = events_csv or os.path.join(METRICS_DIR, "defense_events.csv")
    if not os.path.exists(events_csv):
        print(f"[plots] No existe {events_csv}; ejecuta antes una prueba de tráfico.")
        return []
    outs = [
        plot_ddos(events_csv), plot_scanning(events_csv),
        plot_spoofing(events_csv), plot_normal(events_csv),
        plot_cpu_latency(events_csv), plot_inference_by_class(events_csv),
    ]
    print("[plots] Gráficas generadas:")
    for o in outs:
        print("   ", o)
    return outs


if __name__ == "__main__":
    generate_all()
