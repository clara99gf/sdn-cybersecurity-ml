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

293.852 flujos útiles repartidos en 909 fases de tráfico
(`results/tables/dataset_summary.csv`):

| Clase | Flujos | % | Fases en las que aparece |
|---|---|---|---|
| normal | 135.183 | 46,0 | 675 |
| scanning | 57.714 | 19,6 | 179 |
| ddos | 54.847 | 18,7 | 239 |
| spoofing | 46.108 | 15,7 | 214 |

Se generaron **dos datasets independientes** con idéntica configuración,
para tener una referencia de cuánto varía el resultado entre
generaciones. Random Forest obtuvo F1 macro de 0,726 ± 0,024 y
0,753 ± 0,020 respectivamente. La diferencia entre generaciones (0,027)
es del mismo orden que la dispersión entre particiones dentro de cada
una, lo que indica que el procedimiento de generación es razonablemente
estable. Los resultados que siguen corresponden a la **segunda
generación**, que es la más reciente y la que entrena el modelo
desplegado en la fase 3.

### Fase 2: evaluación offline

Validación cruzada `GroupKFold` de 5 particiones, agrupando por fase.
Gana **Random Forest**, con un **F1 macro de 0,753 ± 0,020**, frente a
0,668 del árbol de decisión y 0,539 de la regresión logística.

| Clase | Precisión | Recall | F1 |
|---|---|---|---|
| scanning | 0,891 | 0,818 | 0,853 |
| normal | 0,721 | 0,885 | 0,795 |
| spoofing | 0,842 | 0,610 | 0,708 |
| ddos | 0,762 | 0,576 | 0,656 |

Las características más determinantes son el número de flujos activos en
el switch, las de ventana temporal (flujos y orígenes distintos hacia un
mismo destino en los últimos 5 s) y la duración del flujo. El coste de
inferencia del modelo elegido es de 0,0033 ms por flujo en lote.

De las 22 características disponibles se conservan las 15 más
importantes dentro de cada partición. Es una decisión de parsimonia, no
de rendimiento ni de coste: con las 22 el F1 macro de Random Forest es
0,7536 y con 15 es 0,7528, una diferencia (0,0008) veinticinco veces
menor que la dispersión entre particiones, mientras que las 7
descartadas suman solo un 6,1 % de la importancia total. La regresión
logística sí mejora con las 22 (0,539 a 0,565), al ser lineal y
aprovechar cualquier señal residual, pero no cambia qué modelo gana.

### Fase 3: detección y mitigación en vivo

Diez repeticiones de la batería completa (los cuatro tipos de tráfico,
30 s cada uno), 14.906 flujos clasificados. **La detección y la
mitigación se miden por separado**, porque el bloqueo altera el tráfico
que se está observando (ver "Limitaciones").

**Detección** (`defense_detection_by_class.csv`), con el mismo criterio
de etiqueta que la fase 2 y por tanto comparable con ella: **F1 macro de
0,814 ± 0,078** entre las diez ejecuciones (0,865 agrupando los 14.906
flujos).

| Clase | Precisión | Recall | F1 |
|---|---|---|---|
| scanning | 0,986 | 0,958 | 0,972 |
| spoofing | 0,879 | 0,860 | 0,869 |
| normal | 0,760 | 0,920 | 0,832 |
| ddos | 0,927 | 0,685 | 0,788 |

**Mitigación** (`defense_mitigation_by_conversation.csv`), medida sobre
la unidad en la que decide el controlador, la conversación MAC origen →
MAC destino: de las 397 conversaciones de ataque, **se bloquearon 387
(recall 0,975)**, con 24 conversaciones legítimas bloqueadas por error
(precisión 0,942, F1 0,958). El primer bloqueo llega **en torno a 2 s**
desde el primer flujo del ataque (1,9 s en spoofing, 2,2 s en DDoS,
2,6 s en scanning), en las 10 de 10 ejecuciones de cada tipo.

El umbral de confirmación (`DEFENSE_MITIGATION_CONFIRMATIONS`) es el
número de sondeos distintos, dentro de una ventana de 5 s, en los que
una conversación debe salir clasificada como ataque antes de bloquearla.
Se usa 3: un ataque real es sostenido y aparece sondeo tras sondeo,
mientras que un error aislado del modelo no se repite, de modo que el
umbral filtra los falsos positivos sin retrasar apenas la respuesta
-con un sondeo por segundo, tres confirmaciones se acumulan en unos
2 s-.

**Impacto en infraestructura**
(`defense_infrastructure_by_traffic.csv`): la CPU del proceso Ryu se
mantiene entre el 4,2 % y el 7,7 % de media según el tipo de tráfico
(con picos puntuales de hasta el 100 % durante el DDoS), la latencia del
plano de control entre 9,1 y 18,6 ms, y la inferencia entre 0,73 y
2,19 ms por flujo.

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

- **Dos generaciones del dataset, no una muestra amplia.** La generación
  es estocástica (se sortean tipos de fase, variantes de ataque y hosts
  atacantes). Con dos generaciones se puede decir que la diferencia
  observada es pequeña (0,726 frente a 0,753), pero no estimar una
  dispersión con rigor: para eso harían falta varias tiradas más, de unas
  cuatro horas cada una, y queda fuera del alcance de este trabajo. La
  dispersión entre particiones de `GroupKFold` (±0,020) mide la
  estabilidad del modelo dentro de una generación, no entre generaciones
  distintas.
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
  debajo de esa tasa, podría pasar desapercibido. Es la principal vía de
  evasión del enfoque y queda como trabajo futuro.
- **Coste de los falsos positivos.** Aunque en flujos son pocos (24 de
  4.065, un 0,6 %), medidos por conversación son 2,4 de las 12,4 activas
  en cada prueba de tráfico normal: alrededor de una de cada cinco
  conversaciones legítimas sufre un corte de 20 s en algún momento. Es la
  principal limitación práctica del sistema: reducirlo más exigiría
  subir el umbral de confirmación o requerir la confirmación en varios
  switches, a costa de retrasar la respuesta ante un ataque real.
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
docs/                   Memoria del TFG y documentación de apoyo
data/                   Dataset (dataset_sdn.csv) y datos procesados
models/                 Modelos entrenados (se generan, no se versionan)
results/                Métricas, tablas y figuras de las fases 2 y 3
logs/, runtime/         Logs y ficheros de coordinación entre procesos
```

## Ficheros versionados

`data/dataset_sdn.csv` se incluye en el repositorio porque generarlo
lleva unas cuatro horas. Solo se versiona la generación con la que se
entrena el modelo desplegado; la otra se conserva fuera del repositorio. Los modelos (`models/*.pkl`) y los datos
procesados no se incluyen: se regeneran en unos tres minutos con
`ml/run_02_ml.py` (además, `random_forest.pkl` supera el límite de
tamaño de GitHub). `results/` sí se incluye, como evidencia directa de
los resultados, incluido `results/events/` con el registro por flujo de
la última batería. En `docs/` está la memoria del TFG, que es el
documento donde se analizan en detalle estos resultados.
