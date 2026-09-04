#!/usr/bin/env python3
"""
feature_windows.py
-------------------
Cálculo de características de "patrón entre flujos" mediante una
ventana deslizante temporal (siempre hacia atrás, nunca al futuro).

Diseñado para usarse en DOS contextos con la MISMA lógica, evitando el
riesgo de "training-serving skew" (que el modelo se entrene con un
cálculo y en producción se sirva con otro ligeramente distinto):

  - AHORA, en modo LOTE (batch): ml/preprocessing.py recorre el CSV ya
    generado, ordenado por tiempo, alimentando un WindowTracker fila a
    fila.
  - EN EL FUTURO, en modo EN VIVO: durante la detección, Ryu podrá
  alimentar el mismo WindowTracker evento a evento conforme lleguen
  nuevos flujos.
"""
from collections import defaultdict, deque


class WindowTracker:
    """Lleva la cuenta de una ventana deslizante temporal (tamaño fijo,
    en segundos) por clave. Cada llamada a add() registra un evento
    nuevo, purga los que ya han caducado, y devuelve:
      - nº total de eventos para esa clave dentro de la ventana.
      - nº de valores DISTINTOS vistos para esa clave dentro de la ventana.

    Ejemplo de uso (modo lote, ver preprocessing.py):
        tracker = WindowTracker(window_seconds=5)
        for src, port, ts in eventos_en_orden_temporal:
            total, distintos = tracker.add(key=src, value=port, now=ts)

    Ejemplo de uso futuro (modo en vivo, dentro de sdn_monitor.py):
        # Un único WindowTracker por proceso (estado en memoria del
        # controlador), alimentado en cada evento real:
        total, distintos = tracker.add(key=ip_src, value=dst_port, now=time.time())
    """

    def __init__(self, window_seconds: float):
        self.window = float(window_seconds)
        self._events = defaultdict(deque)               # key -> deque[(timestamp, value)]
        self._value_counts = defaultdict(lambda: defaultdict(int))  # key -> {value: nº repeticiones}
        self._distinct = defaultdict(int)               # key -> nº de valores distintos en ventana

    def _prune(self, key, now: float) -> None:
        dq = self._events[key]
        vc = self._value_counts[key]
        while dq and (now - dq[0][0]) > self.window:
            _, old_value = dq.popleft()
            vc[old_value] -= 1
            if vc[old_value] == 0:
                del vc[old_value]
                self._distinct[key] -= 1

    def add(self, key, value, now: float):
        """Registra un evento y devuelve (nº_total, nº_distintos) para
        'key' dentro de la ventana, incluyendo este mismo evento."""
        self._prune(key, now)
        dq = self._events[key]
        vc = self._value_counts[key]
        if vc[value] == 0:
            self._distinct[key] += 1
        vc[value] += 1
        dq.append((now, value))
        return len(dq), self._distinct[key]
