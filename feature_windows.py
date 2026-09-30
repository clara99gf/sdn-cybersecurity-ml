#!/usr/bin/env python3
"""
feature_windows.py
------------------
Ventana deslizante temporal con la que se calculan las características
de "patrón entre flujos": cuántos eventos y cuántos valores distintos ha
registrado una clave en los últimos segundos.
 
Lo usan los dos módulos que calculan esas características, en lote
(ml/preprocessing.py, al preparar el dataset) y evento a evento
(controller/live_classifier.py, durante la detección en vivo). Compartir
esta implementación garantiza que una misma característica signifique lo
mismo al entrenar y al clasificar en producción.
"""
from collections import defaultdict, deque


class WindowTracker:
    """Cuenta eventos y valores distintos por clave dentro de una ventana
    temporal de tamaño fijo.
 
    La ventana mira siempre hacia atrás: cada llamada a add() registra un
    evento, descarta los que ya han caducado y devuelve el estado
    actualizado de esa clave.
 
    Ejemplo, para contar puertos distintos por origen en 5 segundos:
        tracker = WindowTracker(window_seconds=5)
        for src, port, ts in events:          # en orden temporal
            total, distinct = tracker.add(key=src, value=port, now=ts)

    """

    def __init__(self, window_seconds: float):
        self.window = float(window_seconds)
        self._events = defaultdict(deque)               # key -> deque[(timestamp, value)]
        self._value_counts = defaultdict(lambda: defaultdict(int))  # key -> {value: repeticiones}
        self._distinct = defaultdict(int)               # key -> valores distintos en la ventana

    def _prune(self, key, now: float) -> None:
        """Descarta los eventos de 'key' anteriores a la ventana.
 
        Mantiene actualizado el recuento de valores distintos: un valor
        deja de contar solo cuando caduca su última aparición.
        """
        dq = self._events[key]
        vc = self._value_counts[key]
        while dq and (now - dq[0][0]) > self.window:
            _, old_value = dq.popleft()
            vc[old_value] -= 1
            if vc[old_value] == 0:
                del vc[old_value]
                self._distinct[key] -= 1

    def add(self, key, value, now: float):
        """Registra un evento y devuelve (total, distintos) para 'key'
        dentro de la ventana, contando este mismo evento."""
        self._prune(key, now)
        dq = self._events[key]
        vc = self._value_counts[key]
        if vc[value] == 0:
            self._distinct[key] += 1
        vc[value] += 1
        dq.append((now, value))
        return len(dq), self._distinct[key]
