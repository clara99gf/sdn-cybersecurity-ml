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
generan además la matriz de confusión de la fase en vivo y las tablas de
resultados.
 
Esas tablas separan DETECCIÓN de MITIGACIÓN, que son dos preguntas
distintas y no se pueden medir sobre lo mismo -en cuanto el controlador
bloquea, deja de observar el tráfico que estaba midiendo-:
 
  - defense_detection_by_class.csv: ¿acierta el modelo la etiqueta de
    cada flujo? Precision/recall/F1 por clase, comparables con la
    validación GroupKFold de la fase 2.
  - defense_mitigation_by_conversation.csv: ¿bloquea lo que debe?
    Conversaciones de ataque bloqueadas, conversaciones legítimas
    bloqueadas por error y tiempo hasta el primer DROP.
  - defense_recall_around_drop.csv: recall por flujo antes y después del
    primer bloqueo, que es lo que explica la diferencia entre las dos
    anteriores.
 
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
    flujos), y conviene que sea un caso típico, no el mejor ni el peor.
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


def _cumulative_attack_plot(events_csv, clase, color, titulo, out_name):
    """Gráfica acumulada de una prueba de ataque, con DOS curvas:
 
      - flujos del ataque (etiqueta real): la actividad que hubo;
      - detectados como ese ataque: lo que vio el modelo.
 
    La separación entre ambas es el error de detección, y el tramo en que
    las dos se aplanan es el ataque cortado por la mitigación."""
    df = _load(events_csv)
    d = _phase(df, clase, one_run=True)
    fig, ax = plt.subplots(figsize=(10, 5))
    if len(d):
        reales = d[d["true_label"] == clase] if "true_label" in d.columns else d
        detect = d[d["predicted_label"] == clase]
        if len(reales):
            ax.plot(reales["t_rel"].to_numpy(), np.arange(1, len(reales) + 1),
                    marker=".", linestyle="-", color=color,
                    label=f"flujos de {clase} (acumulado)")
        if len(detect):
            ax.plot(detect["t_rel"].to_numpy(), np.arange(1, len(detect) + 1),
                    marker=".", linestyle="--", color="#34495e",
                    label="detectados por el modelo (acumulado)")
        _mark_drops(ax, d)
        ax.legend()
    else:
        ax.text(0.5, 0.5, f"(sin datos de la prueba '{clase}')", ha="center",
                va="center", transform=ax.transAxes, color="gray")
    ax.set_xlabel("Tiempo (s)")
    ax.set_ylabel("Flujos acumulados")
    ax.set_title(titulo + _run_suffix(df))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, out_name)
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


def plot_scanning(events_csv):
    """Scanning: flujos del escaneo y detecciones acumuladas.
 
    Se cuentan flujos, no puertos únicos: con un sondeo por segundo cada
    flujo se ve con un solo puerto, así que el número de flujos refleja
    mejor la actividad del escaneo (muchos destinos y puertos) que un
    recuento de puertos distintos."""
    return _cumulative_attack_plot(
        events_csv, "scanning", "#e67e22",
        "Scanning (nmap y sondas ACK con hping3): actividad y mitigación",
        "scanning_ports.png")


def plot_spoofing(events_csv):
    """Spoofing: flujos del ataque y detecciones acumuladas."""
    return _cumulative_attack_plot(
        events_csv, "spoofing", "#8e44ad",
        "Spoofing (ARP/IP): actividad y mitigación",
        "spoofing_detected.png")


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
    # Orden alfabético: el MISMO que usan las matrices de confusión de la
    # fase 2 (viene de LabelEncoder), para poder compararlas de un vistazo.
    labels = sorted(set(CLASSES) & (set(df["true_label"]) | set(df["predicted_label"])))
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
    """TABLA del impacto en infraestructura POR TIPO DE TRÁFICO:

      - CPU media y máxima del proceso Ryu.
      - Latencia del plano de control: del evento OFPFlowStatsReply al
        envío de la regla OFPFlowMod (solo se mide cuando hay mitigación).
      - Tiempo de inferencia del modelo por flujo (media, máximo y
        desviación). Es el coste amortizado: el controlador clasifica de
        una vez todos los flujos de un sondeo, así que el coste fijo de
        cada llamada al modelo se reparte entre los flujos del lote.
      - Nº de mitigaciones aplicadas.
    """
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
    table = pd.DataFrame(rows)
    out = os.path.join(TABLES_DIR, "defense_infrastructure_by_traffic.csv")
    table.to_csv(out, index=False)
    return out, table


def _prf(df, labels):
    """precision/recall/F1/soporte por clase (sklearn), como dicts."""
    from sklearn.metrics import precision_recall_fscore_support
    p, r, f, n = precision_recall_fscore_support(
        df["true_label"], df["predicted_label"], labels=labels, zero_division=0)
    return {c: (p[i], r[i], f[i], int(n[i])) for i, c in enumerate(labels)}


def table_detection(events_csv):
    """TABLA de DETECCIÓN: precision / recall / F1 por clase y su media
    macro (fila macro_avg), sobre todos los flujos clasificados y con el
    mismo criterio de etiqueta que la evaluación offline de la fase 2
    -por eso su F1 macro es el comparable con el de la fase 2-. Si la
    batería se repitió, se suman todas las ejecuciones (la variación
    entre ejecuciones está en table_battery_runs).
 
    Mide SOLO detección: si el modelo acierta la etiqueta de cada flujo.
    Lo relativo a la mitigación (cuándo y qué se bloquea) vive en
    table_mitigation(). Se separan porque son preguntas distintas y porque
    la mitigación altera el tráfico que se mide (ver
    table_recall_around_drop())."""
    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None, None
    labels = [c for c in CLASSES if c in set(df["true_label"])]
    m = _prf(df, labels)
    rows = []
    for c in labels:
        p, r, f, n = m[c]
        rows.append({
            "class": c, "flows": n,
            "precision": round(p, 3), "recall": round(r, 3), "f1": round(f, 3),
        })
    table = pd.DataFrame(rows)
    if len(table) > 1:
        macro = {"class": "macro_avg", "flows": int(table["flows"].sum())}
        for col in ["precision", "recall", "f1"]:
            macro[col] = round(table[col].mean(), 3)
        table = pd.concat([table, pd.DataFrame([macro])], ignore_index=True)
    out = os.path.join(TABLES_DIR, "defense_detection_by_class.csv")
    table.to_csv(out, index=False)
    return out, table


def table_mitigation(events_csv):
    """TABLA de MITIGACIÓN, medida por CONVERSACIÓN (par MAC origen -> MAC
    destino dentro de una prueba), no por flujo.
 
    Por qué por conversación y no por flujo: la unidad sobre la que
    decide el controlador es la conversación -instala un DROP para el par
    de MACs, no para un flujo suelto-. Medir la mitigación por flujo da
    una cifra engañosa: en cuanto se instala el DROP, el ataque queda
    cortado y los flujos que siguen apareciendo son restos sin tráfico,
    que el modelo clasifica como normales. Eso hunde el recall POR FLUJO
    de los ataques que mejor se mitigan, mientras que por conversación la pregunta es la correcta:
    de las conversaciones de ataque que hubo, ¿cuántas se llegaron a
    bloquear, y cuántas legítimas cayeron por error?
 
    Una conversación cuenta como "de ataque" si alguno de sus flujos
    tiene etiqueta real de ataque, y como "bloqueada" si en algún momento
    se le aplicó un DROP. El recall: mide COBERTURA
    (ninguna conversación de ataque se quedó sin bloquear en ningún
    momento), no supresión continua -las reglas duran
    DEFENSE_DROP_TIMEOUT segundos y, si el ataque sigue, la conversación
    se vuelve a detectar y a bloquear-."""
    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None, None
    ataque = set(CLASSES) - {"normal"}
    conv = (df.groupby(["run", "traffic_phase", "eth_src", "eth_dst"])
              .agg(es_ataque=("true_label", lambda s: bool(set(s) & ataque)),
                   bloqueada=("mitigated", "max"))
              .reset_index())
    conv["bloqueada"] = conv["bloqueada"].astype(bool)

    rows = []
    for fase in [c for c in CLASSES if c in set(conv["traffic_phase"])]:
        c = conv[conv["traffic_phase"] == fase]
        d = df[df["traffic_phase"] == fase]
        # Tiempo hasta el primer DROP, medido desde el primer flujo DEL
        # ATAQUE visto por el controlador (no desde el inicio de la
        # prueba: los primeros segundos aún no hay ataque que bloquear).
        # Media entre ejecuciones. En la prueba 'normal' no aplica: no hay
        # ataque, y todo DROP es un falso positivo.
        mitigation_times = []
        if fase != "normal":
            for _, g in d[d["true_label"] == fase].groupby("run"):
                mit = g[g["mitigated"] == 1]
                if len(mit):
                    mitigation_times.append((mit["t"].min() - g["t"].min()).total_seconds())
        rows.append({
            "traffic_phase": fase,
            "conversations": len(c),
            "attack_conversations": int(c["es_ataque"].sum()),
            "attack_blocked": int((c["es_ataque"] & c["bloqueada"]).sum()),
            "attack_not_blocked": int((c["es_ataque"] & ~c["bloqueada"]).sum()),
            "legit_blocked": int((~c["es_ataque"] & c["bloqueada"]).sum()),
            "drops": int((d["mitigated"] == 1).sum()),
            "first_mitigation_s": round(float(np.mean(mitigation_times)), 2) if mitigation_times else "",
            "runs_with_mitigation": f"{len(mitigation_times)}/{d['run'].nunique()}",
        })
    table = pd.DataFrame(rows)

    tp = int((conv["es_ataque"] & conv["bloqueada"]).sum())
    fp = int((~conv["es_ataque"] & conv["bloqueada"]).sum())
    fn = int((conv["es_ataque"] & ~conv["bloqueada"]).sum())
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    total = {
        "traffic_phase": "total",
        "conversations": len(conv),
        "attack_conversations": tp + fn,
        "attack_blocked": tp,
        "attack_not_blocked": fn,
        "legit_blocked": fp,
        "drops": int((df["mitigated"] == 1).sum()),
        "first_mitigation_s": "",
        "runs_with_mitigation": "",
    }
    table = pd.concat([table, pd.DataFrame([total])], ignore_index=True)
    # Precisión/recall/F1 de la DECISIÓN DE BLOQUEAR (no de clasificar);
    # solo tienen sentido sobre el conjunto, así que van en la fila total.
    # Se construyen como listas (y no asignando a table.loc[...] después)
    # porque en pandas 3 una columna creada con "" queda de tipo cadena y
    # rechaza que luego se le meta un número.
    huecos = [""] * (len(table) - 1)
    table["block_precision"] = huecos + [round(prec, 3)]
    table["block_recall"] = huecos + [round(rec, 3)]
    table["block_f1"] = huecos + [round(f1, 3)]

    out = os.path.join(TABLES_DIR, "defense_mitigation_by_conversation.csv")
    table.to_csv(out, index=False)
    return out, table


def table_recall_around_drop(events_csv):
    """TABLA puente entre detección y mitigación: recall POR FLUJO de cada
    ataque ANTES y DESPUÉS del primer DROP de su prueba.

    Es la que explica por qué las dos formas de medir dan números tan
    distintos. Mientras el ataque está en marcha, el modelo lo detecta
    bien; una vez bloqueado, lo que el controlador sigue viendo son
    flujos residuales sin tráfico, indistinguibles de tráfico normal. Sin
    esta tabla, el recall global de un ataque que se mitiga rápido parece
    un fallo del modelo cuando en realidad es consecuencia del éxito de
    la mitigación."""
    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None, None
    rows = []
    for cls in [c for c in CLASSES if c != "normal" and c in set(df["true_label"])]:
        pre_ok = pre_n = post_ok = post_n = 0
        for _, g in df[df["traffic_phase"] == cls].groupby("run"):
            mit = g[g["mitigated"] == 1]
            if not len(mit):
                continue
            t0 = mit["t"].min()
            d = g[g["true_label"] == cls]
            pre, post = d[d["t"] <= t0], d[d["t"] > t0]
            pre_n += len(pre);  pre_ok += int((pre["predicted_label"] == cls).sum())
            post_n += len(post); post_ok += int((post["predicted_label"] == cls).sum())
        if pre_n or post_n:
            rows.append({
                "class": cls,
                "flows_before_drop": pre_n,
                "recall_before_drop": round(pre_ok / pre_n, 3) if pre_n else "",
                "flows_after_drop": post_n,
                "recall_after_drop": round(post_ok / post_n, 3) if post_n else "",
            })
    if not rows:
        return None, None
    table = pd.DataFrame(rows)
    out = os.path.join(TABLES_DIR, "defense_recall_around_drop.csv")
    table.to_csv(out, index=False)
    return out, table


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
    table = pd.DataFrame(rows)
    cols = ["precision_macro", "recall_macro", "f1_macro"]
    # Media y desviación típica (poblacional, igual que np.std en la fase
    # 2) sobre los valores SIN redondear; se redondea solo al final.
    media = {"run": "mean", "flows": round(table["flows"].mean(), 1)}
    std = {"run": "std", "flows": round(table["flows"].std(ddof=0), 1)}
    for c in cols:
        media[c] = table[c].mean()
        std[c] = table[c].std(ddof=0)
    table["flows"] = table["flows"].astype(object)
    table = pd.concat([table, pd.DataFrame([media, std])], ignore_index=True)
    table[cols] = table[cols].astype(float).round(3)
    out = os.path.join(TABLES_DIR, "defense_battery_runs.csv")
    table.to_csv(out, index=False)
    return out, table


def plot_offline_vs_live(events_csv):
    """Compara, CLASE A CLASE, el rendimiento offline (fase 2, validación
    cruzada agrupada) con el del despliegue en vivo (fase 3).
 
    Es la figura que resume el trabajo: cuánto de lo que promete el modelo
    en laboratorio se conserva al desplegarlo sobre tráfico nuevo y con la
    mitigación actuando. Se dibujan recall y F1 -no la precisión, que
    depende de la proporción de clases y en la batería no es la misma que
    en el dataset, así que no sería comparable-.
 
    Necesita results/tables/metrics_by_class.csv (lo genera
    ml/evaluate.py); si no está, se omite sin fallar."""
    ruta_offline = os.path.join(TABLES_DIR, "metrics_by_class.csv")
    if not os.path.exists(ruta_offline):
        return None
    offline = pd.read_csv(ruta_offline)
    # Modelo con mejor F1 macro = el que se despliega en la fase 3.
    ruta_comp = os.path.join(TABLES_DIR, "metrics_comparison.csv")
    if os.path.exists(ruta_comp):
        comp = pd.read_csv(ruta_comp)
        mejor = comp.sort_values("f1", ascending=False).iloc[0]["model"]
    else:
        mejor = offline.groupby("model")["f1"].mean().idxmax()
    offline = offline[offline["model"] == mejor].set_index("class")

    df = _load(events_csv)
    if "true_label" not in df.columns:
        return None
    labels = [c for c in CLASSES if c in set(df["true_label"])
              and c in offline.index]
    if not labels:
        return None
    live = _prf(df, labels)

    x = np.arange(len(labels))
    ancho = 0.35
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5), sharey=True)
    for ax, metrica, idx in [(axes[0], "Recall", 1), (axes[1], "F1", 2)]:
        v_off = [offline.loc[c, metrica.lower()] for c in labels]
        v_live = [live[c][idx] for c in labels]
        ax.bar(x - ancho / 2, v_off, ancho, label="Offline (fase 2)",
               color="#2980b9")
        ax.bar(x + ancho / 2, v_live, ancho, label="En vivo (fase 3)",
               color="#e67e22")
        ax.set_xticks(x)
        ax.set_xticklabels(labels, rotation=20)
        ax.set_title(metrica)
        ax.set_ylim(0, 1)
        ax.grid(axis="y", alpha=0.25)
    axes[0].set_ylabel("Puntuación")
    axes[0].legend(loc="lower right")
    n = df["run"].nunique()
    fig.suptitle(f"Rendimiento por clase: validación offline ({mejor}) frente a "
                 f"detección en vivo" + (f" ({n} ejecuciones)" if n > 1 else ""))
    fig.tight_layout()
    out = os.path.join(FIGURES_DIR, "offline_vs_live_by_class.png")
    fig.savefig(out, dpi=150); plt.close(fig)
    return out


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
    cmp_out = plot_offline_vs_live(events_csv)
    if cmp_out:
        outs.append(cmp_out)
    n_figs = len(outs)
    infra_out, infra_tab = table_infrastructure(events_csv)
    det_out, det_tab = table_detection(events_csv)
    mit_out, mit_tab = table_mitigation(events_csv)
    drop_out, drop_tab = table_recall_around_drop(events_csv)
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
        print("   ", det_out, "  (DETECCIÓN: acierto del modelo por flujo)")
        print(det_tab.to_string(index=False))
    if mit_out:
        outs.append(mit_out)
        print("   ", mit_out, "  (MITIGACIÓN: decisión de bloqueo por conversación)")
        print(mit_tab.to_string(index=False))
    if drop_out:
        outs.append(drop_out)
        print("   ", drop_out, "  (efecto de la mitigación sobre el recall por flujo)")
        print(drop_tab.to_string(index=False))
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
