# Detección y mitigación de amenazas en SDN con Machine Learning (TFG)

Sistema que combina Redes Definidas por Software (SDN) e Inteligencia
Artificial para detectar y mitigar en tiempo real ataques de **scanning**,
**spoofing** (ARP e IP) y **DDoS** en una red emulada con Mininet y
controlada por Ryu (OpenFlow 1.3).

El proyecto se divide en tres fases:

| Fase | Script | Qué hace | Resultado |
|---|---|---|---|
| 1. Dataset | `run_01_dataset.py` | Genera tráfico normal y de ataque en Mininet y registra las estadísticas de flujo que ve el controlador, etiquetadas por flujo | `data/dataset_sdn.csv` |
| 2. Machine Learning | `ml/run_02_ml.py` | Preprocesa, entrena Logistic Regression, Decision Tree y Random Forest, y los evalúa con validación cruzada agrupada por fase | `models/`, `results/` |
| 3. Detección y mitigación | `run_03_defense.py` | El controlador clasifica cada flujo en vivo con el mejor modelo y bloquea las conversaciones de ataque con reglas OpenFlow DROP | `results/events/`, `results/figures/defense/`, `results/tables/` |

- **Instalación**: `./setup.sh` (Ubuntu; instala Mininet, Open vSwitch,
  nmap, hping3, iperf y crea el entorno virtual con Ryu, scapy y
  scikit-learn). `requirements.txt` documenta las versiones exactas con
  las que se obtuvieron estos resultados: para replicarlas,
  `./venv/bin/pip install -r requirements.txt` después de `setup.sh`.
- **Ejecución paso a paso**: [`EJECUCION.md`](EJECUCION.md).
- **Parámetros**: todos centralizados en `config.py`, con una sección por fase.

## Entorno

- Topología en árbol (profundidad 2, fanout 4): 5 switches y 16 hosts,
  enlaces de 10 Mbps.
- Controlador Ryu con reglas reactivas granulares (una regla por flujo)
  y sondeo de estadísticas cada segundo.
- Tráfico normal: `ping` e `iperf` TCP/UDP. Ataques: `nmap` y sondas ACK
  con `hping3` (scanning), `hping3` SYN/UDP/ICMP con varios atacantes
  (DDoS), envenenamiento ARP con scapy e IP spoofing con `hping3 -a`
  (spoofing).

## Resultados

Resumen; el detalle está en `results/` (tablas CSV y figuras) y el
análisis completo, en la memoria del TFG.

### Fase 1: el dataset

293.810 flujos útiles repartidos en 887 fases de tráfico
(`results/tables/dataset_summary.csv`):

| Clase | Flujos | % | Fases en las que aparece |
|---|---|---|---|
| normal | 140.753 | 47,9 | 639 |
| scanning | 61.749 | 21,0 | 200 |
| ddos | 50.553 | 17,2 | 208 |
| spoofing | 40.755 | 13,9 | 216 |

### Fase 2: evaluación offline

Validación cruzada `GroupKFold` de 5 particiones, agrupando por fase.
Gana **Random Forest**, con un **F1 macro de 0,726 ± 0,024**, frente a
0,636 del árbol de decisión y 0,479 de la regresión logística.

| Clase | Precisión | Recall | F1 |
|---|---|---|---|
| normal | 0,719 | 0,879 | 0,791 |
| scanning | 0,868 | 0,788 | 0,826 |
| spoofing | 0,812 | 0,548 | 0,654 |
| ddos | 0,735 | 0,555 | 0,632 |

Las características más determinantes son el número de flujos activos en
el switch, la duración del flujo y las de ventana temporal (orígenes y
destinos distintos en los últimos 5 s). El coste de inferencia del modelo
elegido es de 0,0034 ms por flujo en lote.

### Fase 3: detección y mitigación en vivo

Diez repeticiones de la batería completa (los cuatro tipos de tráfico,
30 s cada uno), 16.099 flujos clasificados. **La detección y la
mitigación se miden por separado**, porque el bloqueo altera el tráfico
que se está observando (ver "Limitaciones").

**Detección** (`defense_detection_by_class.csv`), con el mismo criterio
de etiqueta que la fase 2 y por tanto comparable con ella: **F1 macro de
0,853 ± 0,057** entre las diez ejecuciones (0,860 agrupando los 16.099
flujos).

| Clase | Precisión | Recall | F1 |
|---|---|---|---|
| scanning | 0,972 | 0,956 | 0,964 |
| spoofing | 0,922 | 0,931 | 0,927 |
| normal | 0,738 | 0,920 | 0,819 |
| ddos | 0,908 | 0,610 | 0,730 |

**Mitigación** (`defense_mitigation_by_conversation.csv`), medida sobre
la unidad en la que decide el controlador, la conversación MAC origen →
MAC destino: de las 411 conversaciones de ataque, **se bloquearon 407
(recall 0,99)**, con 33 conversaciones legítimas bloqueadas por error
(precisión 0,925, F1 0,957). El primer bloqueo llega **en torno a 2 s**
desde el primer flujo del ataque (2,0 s en spoofing, 2,1 s en DDoS,
2,5 s en scanning), en las 10 de 10 ejecuciones de cada tipo.

El umbral de confirmación (`DEFENSE_MITIGATION_CONFIRMATIONS`, número de
sondeos distintos en los que una conversación debe salir como ataque
antes de bloquearla) se fijó en 3 a partir de esta medición sobre la
propia batería:

| Confirmaciones | Legítimas bloqueadas | Ataques bloqueados | Precisión | Recall |
|---|---|---|---|---|
| 2 | 48 de 128 | 380 de 384 | 0,888 | 0,990 |
| 3 | 33 de 128 | 407 de 411 | 0,925 | 0,990 |
| 4 | 16 de 128 | 358 de 384 | 0,957 | 0,932 |

Las filas de 2 y 4 confirmaciones proceden de simular la misma lógica
sobre los eventos ya registrados; la de 3 es la ejecución real. Con 4 el
daño colateral baja otro tanto, pero ya se escapan 26 conversaciones de
ataque, y en un IPS perder ataques pesa más que cortar de más.

**Impacto en infraestructura**
(`defense_infrastructure_by_traffic.csv`): la CPU del proceso Ryu se
mantiene entre el 3,9 % y el 11,9 % de media según el tipo de tráfico
(con picos puntuales de hasta el 100 % durante el DDoS), la latencia del
plano de control entre 8,8 y 15,7 ms, y la inferencia entre 0,65 y
2,01 ms por flujo.

## Decisiones de diseño principales

- **Etiquetado por flujo**: cada ataque declara sus actores (atacante,
  víctimas, identidad suplantada) y solo los flujos que los involucran,
  en ambos sentidos, se etiquetan como ataque.
- **Evaluación sin fuga de información**: `GroupKFold` agrupado por fase,
  con escalado y selección de características dentro de cada partición.
- **Mismo cálculo en entrenamiento y en vivo**: la fase 3 reutiliza el
  generador de tráfico de la fase 1, el mismo cálculo de contadores y
  tasas del monitor, el mismo módulo de ventanas temporales
  (`feature_windows.py`) y el mismo criterio de etiquetado, para evitar
  diferencias entre lo que el modelo vio al entrenar y lo que ve en vivo.
- **Mitigación por conversación**: se bloquea el par MAC origen → MAC
  destino, en todos los switches, tras confirmarlo en dos sondeos, y
  con una regla temporal (20 s). Así un falso positivo corta una
  conversación durante un tiempo acotado, no un host entero.
- **Detección y mitigación medidas por separado**: la primera por flujo,
  la segunda por conversación, porque el bloqueo cambia el tráfico que se
  observa a continuación.

## Limitaciones conocidas

- **Una sola generación del dataset.** La generación es estocástica (se
  sortean tipos de fase, variantes de ataque y hosts atacantes), así que
  las cifras corresponden a una única tirada. La dispersión entre
  particiones de `GroupKFold` (±0,024) mide la estabilidad del modelo
  dentro de esa tirada, **no** la variabilidad entre generaciones
  distintas, que no se ha cuantificado. Como referencia de esa
  variabilidad, las diez repeticiones de la fase 3, que sortean los
  mismos elementos, dan ±0,086.
- **La mitigación sesga el recall por flujo.** Una vez instalada la
  regla DROP el ataque queda cortado, y lo que el controlador sigue
  viendo son reglas reactivas anteriores que expiran sin tráfico (las
  reglas DROP en sí se excluyen del procesamiento). Además, cuando la
  regla caduca y el ataque rebrota, nunca recupera la intensidad inicial
  porque se le vuelve a cortar enseguida. Como el modelo reconoce el
  DDoS sobre todo por volumen, su recall por flujo (0,610) queda muy por
  debajo del que tiene mientras el ataque está a pleno rendimiento
  (0,820 hasta el primer bloqueo, `defense_recall_around_drop.csv`). Es
  consecuencia del éxito de la mitigación, no de un fallo del modelo.
- **La detección en vivo no es independiente de la política de
  mitigación.** Al subir el umbral de confirmación de 2 a 3, el bloqueo
  llega más tarde, el ataque se observa más tiempo a plena intensidad y
  el F1 macro de detección sube de 0,819 a 0,860 sin tocar el modelo. Las
  cifras de detección de la fase 3 hay que leerlas junto al umbral con el
  que se obtuvieron.
- **Detección por volumen.** El modelo identifica el DDoS principalmente
  por su tasa de paquetes, así que un ataque lento y sostenido, por
  debajo de esa tasa, podría pasar desapercibido. Es la principal vía de
  evasión del enfoque y queda como trabajo futuro.
- **Coste de los falsos positivos.** Aunque en flujos son pocos (33 de
  4.073, un 0,8 %), medidos por conversación son 3,2 de las 12,8 activas
  en cada prueba de tráfico normal: una de cada cuatro conversaciones
  legítimas sufre un corte de 20 s en algún momento. Es la principal
  limitación práctica del sistema, y la razón de haber subido el umbral
  de confirmación a 3.
- **El recall de mitigación mide cobertura, no supresión continua**: una
  conversación cuenta como bloqueada si se le aplicó un DROP en algún
  momento. Como las reglas duran 20 s, un ataque prolongado se bloquea,
  se desbloquea y se vuelve a bloquear.
- Las fases de ataque se generan sin tráfico legítimo concurrente, y en
  la fase 3 el DDoS se lanza sin la intensidad `--flood` (satura la CPU
  con el modelo clasificando en vivo), que sí está en el dataset.
- El criterio de actores incluye a la víctima: en DDoS y spoofing, un
  flujo entre la víctima y un host ajeno también contaría como ataque.
- La vinculación IP↔MAC de referencia (`ip_mac_consistent`) se toma de
  Mininet; en una red real vendría de DHCP o de un inventario.
- Los tiempos de inferencia offline (lotes de decenas de miles de flujos)
  y en vivo (lotes de unos pocos) no son comparables directamente: la
  diferencia es el coste fijo por llamada, no el modelo.

## Estructura

```
config.py               Parámetros y rutas de todo el proyecto
feature_windows.py      Ventana temporal deslizante (compartida por fases 2 y 3)
run_01_dataset.py       Fase 1: controlador + red + generación del dataset
run_03_defense.py       Fase 3: menú de detección y mitigación en vivo
setup.sh / setup.py     Instalación (dependencias de sistema, venv, pip install -e .)
controller/
  sdn_monitor.py        Fase 1: app Ryu que registra y etiqueta los flujos
  sdn_defense.py        Fase 3: app Ryu que clasifica en vivo y mitiga
  live_classifier.py    Fase 3: preprocesado idéntico al del entrenamiento, flujo a flujo
mininet_lab/
  topology.py           Fase 1: topología Mininet
  traffic_generator.py  Tráfico normal y de ataque (fases 1 y 3)
  arp_spoof.py          ARP spoofing multi-víctima (scapy)
ml/
  preprocessing.py      Limpieza, ventanas temporales, codificación
  train.py              Entrenamiento de los tres modelos
  evaluate.py           GroupKFold, métricas, matrices de confusión, coste
  run_02_ml.py          Fase 2 completa en un comando
  utils.py              Guardado y carga de datos y modelos
defense/
  traffic.py            Fase 3: lanza el tráfico de cada prueba
  plots.py              Fase 3: gráficas y tablas de resultados
data/                   Dataset (dataset_sdn.csv) y datos procesados
models/                 Modelos entrenados (se generan, no se versionan)
results/                Métricas, tablas y figuras de las fases 2 y 3
logs/, runtime/         Logs y ficheros de coordinación entre procesos
```

## Ficheros versionados

`data/dataset_sdn.csv` se incluye en el repositorio porque generarlo
lleva unas cuatro horas. Los modelos (`models/*.pkl`) y los datos
procesados no se incluyen: se regeneran en unos tres minutos con
`ml/run_02_ml.py` (además, `random_forest.pkl` supera el límite de
tamaño de GitHub). `results/` sí se incluye, como evidencia directa de
los resultados, incluido `results/events/` con el registro por flujo de
la última batería.
