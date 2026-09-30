# Detección y mitigación de amenazas en SDN con Machine Learning 

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

- **Instalación**: `./setup.sh` (Ubuntu, Python 3.8-3.10; instala
  Mininet, Open vSwitch, nmap, hping3, iperf y crea el entorno virtual
  con Ryu, scapy y scikit-learn, aplicando el parche de compatibilidad
  que Ryu necesita con eventlet). `requirements.txt` documenta las
  versiones exactas con las que se obtuvieron estos resultados: para
  replicarlas, `./venv/bin/pip install -r requirements.txt` después de
  `setup.sh`.
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

Los resultados completos se encuentran en `results/` y el análisis detallado
en la memoria del TFG, en `docs/`.

### Fase 1: el dataset

Se obtuvieron **293.852 flujos útiles**, distribuidos en **909 fases de
tráfico**, correspondientes a tráfico normal, scanning, DDoS y spoofing.

### Fase 2: evaluación offline

La evaluación mediante `GroupKFold` de 5 particiones, agrupando por fase,
seleccionó **Random Forest** como modelo con mejor rendimiento, con un
**F1 macro de 0,753 ± 0,020**.

### Fase 3: detección y mitigación en vivo

En 10 ejecuciones de la batería completa, la detección obtuvo un
**F1 macro de 0,814 ± 0,078**.

A nivel de mitigación, se bloquearon **387 de 397 conversaciones de ataque
(recall 0,975)**. Se produjeron además 24 bloqueos de conversaciones
legítimas.

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
  destino, en todos los switches, tras confirmarlo en tres sondeos, y
  con una regla temporal (20 s). Así un falso positivo corta una
  conversación durante un tiempo acotado, no un host entero.
- **Detección y mitigación medidas por separado**: la primera por flujo,
  la segunda por conversación, porque el bloqueo cambia el tráfico que se
  observa a continuación.

## Limitaciones conocidas

- **Dos generaciones del dataset, no una muestra amplia.** La generación
  es estocástica (se sortean tipos de fase, variantes de ataque y hosts
  atacantes). Con dos generaciones se puede decir que la diferencia
  observada es pequeña (0,726 frente a 0,753), pero no estimar una
  dispersión con rigor: para eso harían falta varias tiradas más, de unas
  cuatro horas cada una, y queda fuera del alcance de este trabajo.
- **La batería de la fase 3 también es estocástica.** Cada ejecución
  sortea atacantes, víctimas y variantes de cada ataque, y el F1 macro
  por ejecución varía entre 0,672 y 0,927 dentro de una misma batería
  (`defense_battery_runs.csv`). Por eso las cifras se dan siempre con su
  dispersión entre ejecuciones, y una ejecución aislada no debe tomarse
  como representativa.
- **La mitigación sesga el recall por flujo.** Una vez instalada la
  regla DROP el ataque queda cortado, y lo que el controlador sigue
  viendo son reglas reactivas anteriores que expiran sin tráfico (las
  reglas DROP en sí se excluyen del procesamiento). Además, cuando la
  regla caduca y el ataque rebrota, nunca recupera la intensidad inicial
  porque se le vuelve a cortar enseguida. Como el modelo reconoce el
  DDoS sobre todo por volumen, su recall por flujo (0,685) queda por
  debajo del que tiene mientras el ataque está a pleno rendimiento
  (0,774 hasta el primer bloqueo, `defense_recall_around_drop.csv`). Es
  consecuencia del éxito de la mitigación, no de un fallo del modelo.
- **La detección en vivo no es independiente de la política de
  mitigación.** Cuanto antes se bloquee una conversación, menos flujos
  de ese ataque llega a observar el controlador, y esos flujos son
  además los de menor intensidad. Las cifras de detección de la fase 3
  hay que leerlas junto al umbral de confirmación con el que se
  obtuvieron.
- **Detección por volumen.** El modelo identifica el DDoS principalmente
  por su tasa de paquetes, así que un ataque lento y sostenido, por
  debajo de esa tasa, podría pasar desapercibido.
- **Coste de los falsos positivos.** Aunque en flujos son pocos (24 de
  4.065, un 0,6 %), medidos por conversación son 2,4 de las 12,4 activas
  en cada prueba de tráfico normal: alrededor de una de cada cinco
  conversaciones legítimas sufre un corte de 20 s en algún momento. Reducirlo más podría requerir subir el umbral de confirmación o requerir la confirmación en varios
  switches, a costa de retrasar la respuesta ante un ataque real.
- **El recall de mitigación mide cobertura, no supresión continua**: una
  conversación cuenta como bloqueada si se le aplicó un DROP en algún
  momento. Como las reglas duran 20 s, un ataque prolongado se bloquea,
  se desbloquea y se vuelve a bloquear.
- Las fases de ataque se generan sin tráfico legítimo concurrente, y en
  la fase 3 el DDoS se lanza sin la intensidad `--flood` (satura la CPU
  del entorno de emulación de red), que sí está en el dataset.
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
docs/                   Memoria del TFG 
data/                   Dataset (dataset_sdn.csv) y datos procesados
models/                 Modelos entrenados 
results/                Métricas, tablas y figuras de las fases 2 y 3
logs/, runtime/         Logs y ficheros de coordinación entre procesos
```

## Ficheros versionados

Los modelos (`models/*.pkl`) y los datos
procesados no se incluyen: se regeneran en unos tres minutos con
`ml/run_02_ml.py`. `results/` sí se incluye, como evidencia directa de
los resultados, incluido `results/events/` con el registro por flujo de
la última batería. En `docs/` está la memoria del TFG, que es el
documento donde se analizan en detalle estos resultados.
