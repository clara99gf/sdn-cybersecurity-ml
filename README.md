# Dataset SDN para detección de amenazas (TFG)

Genera un CSV con características de flujos OpenFlow etiquetadas como
`normal`, `scanning`, `spoofing` o `ddos`, a partir de una topología en
árbol emulada en Mininet y controlada por Ryu.

- **Instalación**: `setup.sh`
- **Ejecución**: `EJECUCION.md`
- **Configuración centralizada**: `config.py`

**Nota sobre `data/dataset_sdn.csv`**: a diferencia de lo habitual (no
solerlo versionar), este CSV **sí está incluido en el repositorio** a
propósito -genera tarda varias horas (ver más abajo), y el tribunal del
TFG no debería tener que regenerarlo para revisar el proyecto-. Los
artefactos derivados (`data/processed/`, `models/*.pkl`) NO se
versionan -se regeneran en ~3 minutos con `ml/run_02_ml.py`, y
`random_forest.pkl` pesa ~245MB sin límite de profundidad, superando
el límite de 100MB de GitHub-. `results/` (tablas y gráficas) sí se
versiona -pesa poco y es evidencia directa sin ejecutar nada-.

## Estructura

```
config.py                 # Rutas y parámetros compartidos por todo el proyecto
feature_windows.py         # WindowTracker: ventana deslizante temporal, compartida entre ml/ y (futuro) controller/
run_01_dataset.py                  # Lanza controlador + red + generación con un solo comando
setup.py                    # Instalación editable del proyecto (pip install -e .)
setup.sh                     # Instala dependencias de sistema, crea el venv y ejecuta setup.py
data/                          # CSV del dataset generado (data/dataset_sdn.csv) y data/processed/ (ver ml/)
logs/                           # Logs del controlador y de la generación de tráfico
runtime/                         # Estado efímero compartido (etiqueta de fase activa)
controller/
  __init__.py
  sdn_monitor.py               # App Ryu: switch L2 + monitor periódico -> CSV
mininet_lab/
  __init__.py
  topology.py                   # Levanta la topología y lanza la generación
  traffic_generator.py          # Orquesta las fases de tráfico intercaladas
  arp_spoof.py                   # Script de spoofing ARP (usado por traffic_generator)
ml/
  __init__.py
  utils.py                       # Persistencia de datos/artefactos (data/processed/, models/)
  preprocessing.py               # Limpieza, codificación, selección de características
  train.py                       # Entrena Logistic Regression, Decision Tree, Random Forest
  evaluate.py                    # Métricas, matrices de confusión, coste computacional
  run_02_ml.py                    # Orquestador: preprocessing -> train -> evaluate en un comando
models/                         # Modelos y artefactos entrenados (.pkl) -generado, no versionado-
results/
  figures/                       # Gráficas (comparativa de métricas, matrices de confusión...)
  tables/                        # Tablas en CSV (métricas, coste computacional)
```

> Nota: las dependencias Python (`ryu`, `scapy` para la generación;
> `scikit-learn`, `pandas`, `matplotlib`, `joblib` para `ml/`) están
> declaradas en `setup.py` (`install_requires`), no en un
> `requirements.txt` aparte -una sola fuente de dependencias-.


> Nota: `data/`, `logs/` y `runtime/` guardan su contenido fuera de
> `/tmp` a propósito. Si ejecutas todo con `sudo`, algunos sistemas
> aíslan `/tmp` por sesión, de forma que un fichero escrito por root ahí
> puede no verse luego desde tu shell normal; dentro del proyecto no
> pasa eso.

> Nota de nombres: la carpeta se llama `mininet_lab/` (no `mininet/`)
> a propósito, para no chocar con el paquete real `mininet` que se
> importa en `topology.py`.

## Sobre `setup.py`

`setup.sh` ya lo instala automáticamente (`pip install -e .` dentro
del venv), así que no tienes que hacer nada extra. Lo que aporta:
convierte el proyecto en un paquete instalado en modo editable, de
forma que `import config`, `from controller import sdn_monitor`, etc.
funcionan de forma nativa desde cualquier sitio -incluido un notebook
de preprocesado/entrenamiento fuera de este árbol de carpetas- sin
depender de la carpeta desde la que ejecutes algo. No es
imprescindible para que `run_01_dataset.py` funcione (cada script ya se
resuelve solo con un pequeño `sys.path.insert()` como red de
seguridad), pero es la forma "correcta" de reutilizar `config.py`
-por ejemplo, para leer `CSV_FILE` o `LABEL_FILE`- desde fuera del
proyecto sin repetir rutas a mano.

## Cuántas filas obtienes y cuándo se para (`TARGET_ROWS`, `MAX_ROWS_PER_PHASE`)

Cada fila del CSV corresponde a **un flujo activo en un switch en un
instante de sondeo**, y el ritmo al que se generan puede ser muy
distinto entre fases (una fase con muchos flujos activos simultáneos
puede generar muchísimas más filas que otra en el mismo tiempo). Dos
mecanismos controlan esto en `config.py`:

- `TARGET_ROWS = 50000`: en cuanto el CSV alcanza esa cifra, la
  generación se corta sola, aunque no haya pasado `TOTAL_DURATION`.
  `TOTAL_DURATION` pasa a ser solo un techo de seguridad.
- `MAX_ROWS_PER_PHASE = 1500`: ninguna fase individual puede aportar
  más de esta cifra. Si una fase se dispara (por el motivo que sea) y
  empieza a generar muchas más filas de lo normal, se corta antes de
  agotar su duración -así una sola fase no puede acaparar el dataset,
  y `TARGET_ROWS` se reparte entre muchas más fases distintas, dando
  más variedad-. Ponlo a `None` para desactivarlo.
- `MIN_PHASE_DURATION` / `MAX_PHASE_DURATION` están en 10-25s: fases
  cortas, para muchas transiciones entre clases.

Cada ejecución además **elimina** el CSV anterior por defecto (ver
`RESET_DATASET_ON_START` / `ARCHIVE_PREVIOUS_DATASET` más abajo).

## Por qué el DDoS ya no usa `--rand-source` (y por qué eso NO bastaba)

`hping3 --rand-source` cambia la IP origen en cada paquete, y como
hacemos match por `ipv4_src` eso ya disparaba una entrada de flujo
nueva por paquete. Pero había una causa **más grave todavía**: por
defecto, `hping3` también cambia el **puerto origen** en cada paquete
aunque no uses `--rand-source`, y como también hacemos match por
`tcp_src`, eso solo ya bastaba para generar miles de flujos en
segundos (fue lo que produjo las ~27.000 filas en una sola fase de
54s). Ahora todos los floods usan `-k -s <puerto>` para fijar el
puerto origen, así que cada atacante genera un puñado de flujos
estables con `pps`/`bps` muy altos -el patrón real que quieres que el
modelo aprenda-, no miles de flujos de un paquete cada uno.

## Variedad dentro de cada clase, no solo entre fases

Cada función de tráfico ahora elige aleatoriamente entre varias
variantes internas, para que el dataset no dependa solo de cuántas
fases distintas te dé tiempo a ejecutar:

- **normal**: alterna `ping`, `iperf` TCP e `iperf` UDP (con distintos
  anchos de banda) entre pares de hosts aleatorios.
- **scanning**: combina distintos tipos de escaneo (`-sS`, `-sT`,
  `-sU`, rango de puertos) con distintas plantillas de velocidad
  (`-T2` sigiloso a `-T5` agresivo).
- **spoofing**: alterna entre dos mecanismos distintos -ARP spoofing
  (envenenamiento de caché, como antes) e **IP spoofing** (paquetes
  TCP con IP origen falsificada vía `hping3 -a`, un mecanismo de
  suplantación distinto y complementario)-.
- **ddos**: combina el protocolo (`SYN`/`UDP`/`ICMP`) con la
  intensidad (`--flood` a máxima velocidad, o una tasa acotada
  ~500 pps), para que el dataset no tenga solo el extremo más agresivo.

Con `MIN_PHASE_DURATION`/`MAX_PHASE_DURATION` en 15-40s (antes 30-90s)
y `TARGET_ROWS = 50000` (antes 12.000), ahora deberían darte tiempo
muchas más fases -y con más variedad interna en cada una- antes de
alcanzar el objetivo.

## El "hueco" entre fases (pkill y la etiqueta)

Aunque el vaciado automático de flujos (ver más abajo) ya evita que
flujos *viejos* se cuelen etiquetados con la fase nueva, quedaba un
margen pequeño: el vigilante de la etiqueta solo comprueba cada 0.5s,
así que un proceso recién matado con `pkill` podía tener paquetes
"en vuelo" que llegasen justo después de que la etiqueta ya hubiera
cambiado. Por eso cada fase termina con una pequeña pausa de
asentamiento (`PHASE_SETTLE_SECONDS`, 1.5s por defecto) **antes** de
pasar a la siguiente fase (que es cuando se cambia la etiqueta): así,
si queda algún paquete rezagado, se sigue contando -correctamente-
como parte de la fase que acaba de terminar.



## Características incluidas en el CSV

Identificación: `timestamp`, `dpid`, MACs, `eth_type`.

Capa 3/4: `ip_src`, `ip_dst`, `ip_proto`, puertos TCP/UDP.

Campos ARP (clave para detectar spoofing): `arp_opcode`, `arp_spa`,
`arp_tpa`, `arp_sha` — permiten ver, por ejemplo, una misma MAC
anunciando IPs distintas o una alta tasa de respuestas ARP no
solicitadas.

Estadísticas del flujo: `duration_sec/nsec`, `idle_timeout`,
`hard_timeout`, `packet_count`, `byte_count`.

Características derivadas (las más útiles para diferenciar clases):
- `packet_count_per_second` / `byte_count_per_second`: muy altos en
  DDoS y en escaneos agresivos.
- `avg_packet_size`: los floods (ICMP/SYN) suelen tener paquetes
  pequeños y homogéneos; el tráfico normal es más variable.
- `flow_count_per_dpid`: un scanning genera muchos flujos de corta
  duración en poco tiempo sobre el mismo switch.

`label`: la clase de la fila (`normal`, `scanning`, `spoofing`, `ddos`),
tomada de la fase de tráfico activa en el momento del muestreo.

## Contaminación de etiquetas entre fases (importante)

`OFPFlowStatsRequest` devuelve **todos** los flujos activos en el
switch, no solo los de la fase en curso. Como una entrada de flujo
puede seguir viva hasta `FLOW_HARD_TIMEOUT` segundos después de
creada, si la fase cambiaba justo antes de que expirase (p. ej. de
`scanning` a `spoofing`), esa fila quedaba etiquetada con la fase
nueva aunque el tráfico real fuera de la anterior — por eso podías ver
filas `spoofing` con pinta de escaneo de puertos.

El controlador ahora vigila `runtime/current_label.txt` y, en cuanto
detecta un cambio de fase, **vacía activamente la tabla de flujos**
de cada switch (en vez de esperar a que expiren solas) y reinicia el
histórico de tasas (`pps`/`bps`). Así cada fase empieza con la tabla
limpia y las filas que veas etiquetadas como `spoofing` deberían ser
ya, casi en su totalidad, tramas ARP reales.

## Sobre el tráfico de arranque (`pingAll`)

El `pingAll()` inicial en `topology.py` se ejecuta *antes* de que
exista `runtime/current_label.txt`, así que el controlador etiqueta
esas filas como `normal` por defecto — lo cual es correcto, es
tráfico benigno de comprobación de conectividad. Además, con el
vaciado automático de flujos al cambiar de fase, en cuanto arranca la
primera fase de ataque se limpia cualquier resto de ese `pingAll()`,
así que no hace falta preocuparse por él.

## Leer bien el log: "filas" es acumulado, no por fase

El número `filas: X/Y` que se imprime al empezar cada fase es el total
acumulado en el CSV **antes** de esa fase (el resultado de la fase
anterior), no lo que va a generar la fase que arranca. Para saber
cuánto aportó una fase concreta, resta el valor de dos líneas
consecutivas. Si compruebas `wc -l` a mitad de una fase que acaba de
empezar, verás un número casi igual al de la fase anterior -no
significa que esa fase genere poco, solo que aún no ha tenido tiempo-.

## Por qué `normal` podía generar muchas más filas de las esperadas

`ping`/`iperf` se lanzaban en segundo plano (`&`) sin esperar a que
terminase cada uno antes de la siguiente iteración del bucle, así que
las conversaciones se solapaban y se iban acumulando conexiones
simultáneas; además se relanzaba un servidor `iperf` nuevo en cada
iteración aunque ya hubiera uno corriendo en ese host. Ahora
`ping`/`iperf` (cliente) van sin `&` -cada conversación termina antes
de la siguiente- y el servidor `iperf` se reutiliza por host en vez de
relanzarse. También se limitó el ancho de banda de los enlaces
(`LINK_BANDWIDTH_MBPS = 10` en `config.py`): sin límite, un `iperf` TCP
satura el enlace software de Mininet a velocidades poco realistas
(varios Gbps), lo que además hacía que el tráfico "normal" pareciera
casi tan agresivo como un DDoS en `pps`/`bps`.

## Solo un `dataset_sdn.csv`, sin archivos por fecha

Por defecto (`ARCHIVE_PREVIOUS_DATASET = False` en `config.py`) cada
arranque del controlador **borra** el `data/dataset_sdn.csv` anterior
y empieza uno limpio, así que solo tienes el de la ejecución actual.
Si en algún momento quieres conservar el histórico de ejecuciones
anteriores en vez de perderlo, pon `ARCHIVE_PREVIOUS_DATASET = True` y
se archivarán con timestamp (`dataset_sdn_20260824_211043.csv`) en vez
de borrarse.

## Sobre la revisión de calidad del CSV (filas agregadas, ceros, tasas a 0)

**Nota rápida sobre `timestamp` (arreglado)**: Python omite los
microsegundos en `datetime.now().isoformat()` cuando su valor da
exactamente 0 (1 entre un millón de posibilidades, pero con decenas de
miles de filas puede tocar). Eso dejaba alguna fila suelta con formato
`...T20:06:17` en vez de `...T20:06:17.534000`, rompiendo un parseo con
formato de fecha fijo (aunque `pd.to_datetime(..., format="mixed")` lo
resuelve sin problema). Ahora se fuerza `timespec="microseconds"` para
que el formato sea siempre consistente.



Si te has fijado en cosas como filas sin `eth_src`/`ip_src`, muchas
filas de `scanning`/`spoofing` con `packet_count=0`, o `ddos` con
`packet_count` alto pero `pps`/`bps` en `0.0`, aquí está el porqué de
cada una (dos se arreglaron en el propio script, una es esperable y se
trata en el preprocesado):

- **Filas sin `eth_src`/`ip_src`/etc. (arreglado)**: eran la regla de
  *table-miss* del switch (prioridad 0, match comodín) colándose en
  las estadísticas -es un contador agregado del switch, no un flujo
  real-. Ahora se excluye explícitamente al escribir el CSV.

- **`ddos` con miles de paquetes pero `pps`/`bps = 0.0` (arreglado)**:
  nuestro cálculo de tasa no depende de `duration_sec`/`duration_nsec`
  del flujo, sino de la diferencia de tiempo entre dos sondeos
  consecutivos del MISMO flujo. El problema real era que, la PRIMERA
  vez que veíamos un flujo (sin sondeo previo con el que comparar), se
  forzaba `0.0` aunque ya llevara miles de paquetes acumulados -algo
  muy común en DDoS, donde un flujo puede acumular mucho tráfico antes
  de que le toque su primer sondeo-. Ahora, en ese caso, se usa la
  duración propia que reporta el switch (`duration_sec + duration_nsec`)
  para estimar la tasa en vez de forzar cero.

- **`scanning`/`spoofing` con `packet_count=0` en muchas filas
  (mitigado, pero es en parte esperable)**: en OpenFlow reactivo, el
  paquete que dispara la instalación de una regla nueva NO lo cuenta
  el propio switch en las estadísticas de esa regla -la regla no
  existía todavía cuando llegó-; solo se cuentan los paquetes
  *siguientes* que la reutilizan. Para un escaneo de puertos (un único
  paquete SYN por puerto) eso significa que, sin más, cada flujo
  quedaría en `0/0` para siempre. Ahora el controlador lleva la cuenta
  de ese "paquete invisible" y lo suma al leer las estadísticas, así
  que deberías ver bastantes menos ceros. Aun así, es normal y
  esperable que sigan existiendo flujos genuinamente de 1 paquete
  (p. ej. un único probe SYN sin respuesta): eso no es un fallo de
  cálculo, es la realidad del tráfico -trátalo en el preprocesado como
  cualquier otra fila de bajo volumen, no como un dato corrupto-.

- **`pps`/`bps = 0.0` en flujos con duración y `packet_count` grandes
  (arreglado, bug distinto del anterior)**: cuando un flujo expira
  (`FLOW_HARD_TIMEOUT`) y se reinstala desde cero mientras el tráfico
  sigue activo (misma IP/puerto, típico en un DDoS o spoofing largo),
  sus contadores vuelven a empezar en un número pequeño. El
  controlador seguía comparando contra la ÚLTIMA muestra guardada de
  la instancia ANTERIOR (con contadores más grandes), dando una resta
  negativa que se recortaba a `0.0` de forma incorrecta. Ahora se
  detecta ese "reinicio" (si `packet_count` es menor que la muestra
  guardada) y se usa la duración propia del flujo para estimar la tasa
  en lugar de comparar contra una muestra obsoleta.

- **`avg_packet_size` por encima de la MTU real (mitigado, límite
  conocido)**: en Mininet, las interfaces virtuales suelen tener
  activadas TSO/GSO/GRO (segmentación diferida del kernel), lo que
  hace que OVS cuente "super-paquetes" de varios KB como si fueran
  uno solo, inflando la media muy por encima de los ~1500 bytes reales
  de la MTU. Se ha intentado en dos capas: desactivar TSO/GSO/GRO en
  hosts y switches (`ethtool -K`), y además acotar explícitamente el
  tamaño máximo de "super-paquete" que el kernel puede formar
  (`ip link set ... gso_max_size 1514`) -por si el datapath de Open
  vSwitch reenvía un GSO ya generado sin trocearlo aunque las
  interfaces visibles lo tengan desactivado-. Con ambas capas, en la
  última prueba real quedó en el **0.43% de las filas** (48 de 11.064,
  todas de un mismo patrón: flujos iperf TCP de `normal_traffic`). Es
  un límite conocido y bastante documentado de los entornos de
  emulación software como Mininet -mencionarlo así en la memoria del
  TFG es razonable-, no algo que se pueda garantizar al 100% desde el
  generador. Si tras esto sigue apareciendo algún resto, lo más
  práctico es tratarlo en el preprocesado (recortar `avg_packet_size`
  al valor de MTU, o simplemente eliminar esas pocas filas) en vez de
  seguir persiguiéndolo en el origen.

- **Tráfico ARP etiquetado como `ddos`/`scanning` (mitigado)**: si el
  host atacante no tenía la MAC de la víctima/objetivo en caché, esa
  resolución ARP ocurría ya con la etiqueta de ataque puesta -tráfico
  legítimo coleado como si fuera parte del ataque-. Ahora
  `ddos_traffic`/`scanning_traffic` resuelven el ARP de antemano
  (mientras la etiqueta sigue siendo la de la fase anterior) antes de
  cambiar a la etiqueta de ataque.

## El bug más serio hasta ahora: procesos de ataque que no morían del todo

Confirmado con datos reales que me pasaste: un mismo flujo UDP
(`10.0.0.X:5100+i -> 10.0.0.10:80`, el puerto FIJO que usa nuestro
DDoS) aparecía con `packet_count` **subiendo sin parar** a través de
`scanning` -> `spoofing` -> `normal`, sin cortarse nunca. Un DDoS que
literalmente nunca se paraba y sangraba tráfico real a las fases
siguientes, mal etiquetado con lo que tocara en cada momento. La causa:
`pkill -f <nombre>` (incluso con `-9`) mata por patrón de texto sobre
la línea de comandos, y en la práctica no siempre mataba el proceso a
tiempo. Esto también explica `avg_packet_size` idéntico entre clases
que no deberían parecerse (sigue siendo tráfico del ataque anterior) y
picos raros de `flow_count_per_dpid`.

**Arreglo real**: ahora los ataques de larga duración (`hping3` de
ddos/ip-spoofing, `arp_spoof.py`) se lanzan capturando su **PID exacto**
(`echo $!` justo después de lanzarlos en segundo plano) y se matan por
ESE PID concreto con SIGKILL -mucho más fiable que buscar por nombre-,
manteniendo el `pkill -9` por patrón como red de seguridad adicional
encima, no como único mecanismo.

## Segundo bug serio: la etiqueta no se reseteaba al arrancar

Explica los tramos ARP con `packet_count=0` y `flow_count_per_dpid=162`
etiquetados como `ddos` que también señalaste: ese `162` encaja
perfectamente con el `pingAll()` inicial (240 pares de hosts), no con
nuestro `_arp_warmup` (que solo toca 2-4 pares). El problema es que
`runtime/current_label.txt` no se reseteaba al arrancar el controlador,
así que si una ejecución anterior se interrumpió (con Ctrl+C, como ha
pasado varias veces probando esto) a mitad de una fase, el fichero se
quedaba con esa etiqueta puesta. En la ejecución SIGUIENTE, todo el
`pingAll()` de arranque -antes de que el generador de tráfico llame a
`set_label()` por primera vez- se etiquetaba con la etiqueta vieja.
Arreglado: el controlador escribe `"warmup"` (no `"normal"`) en ese fichero nada más
arrancar.

## Sobre la segunda revisión de calidad (matriz de problemas)

Gran parte de lo que señalaba viene de estos dos bugs (procesos que no
morían + etiqueta no reseteada), así que debería quedar resuelto con
los arreglos anteriores. Sobre los puntos más técnicos:

- **"pps/bps=0.0 porque se divide por duration_sec truncado sin sumar
  duration_nsec"**: no es el mecanismo real (nuestro cálculo no divide
  por duration_sec en absoluto, ver más arriba el bug que sí
  encontramos con el reinicio de flujos), pero el síntoma que
  señalaban era real y ya está corregido.
- **`avg_packet_size = 42.0` "paquetes vacíos"**: es correcto -un
  `hping3` sin `-d` manda paquetes sin payload (14+20+8=42 bytes para
  UDP), y muchos floods reales hacen justo eso para maximizar la tasa
  de paquetes-. No es un error del extractor, es realista para ese
  tipo de tráfico. El problema era que aparecía también en filas que
  NO deberían tener ese patrón (por el bug de arriba).
- **`flow_count_per_dpid` como "ventana temporal mal definida"**: es
  una observación de diseño razonable -ahora mismo es una foto
  instantánea (flujos activos en ese momento), no una tasa por
  ventana de tiempo-. Con el bug de los procesos colgados arreglado
  debería comportarse de forma mucho más sensata por fase; si más
  adelante quieres una métrica de "flujos nuevos en el último

  segundo" en vez de "flujos activos ahora mismo", es más sencillo
  calcularla en el preprocesado a partir de `timestamp` que cambiar
  cómo la genera el controlador.
- **Filas ARP con `packet_count=0` en `spoofing`**: deberían haberse
  reducido ya con el arreglo del "paquete invisible" de la ronda
  anterior; de paso, ahora cada conversación ARP tiene una clave propia
  (antes dos conversaciones ARP distintas entre el mismo par de MACs
  podían compartir el mismo contador interno).

## Si una clase no aparece en el CSV, o el controlador no arranca

Revisa `logs/traffic_generator.log`: ahí quedan registrados los
comandos lanzados y sus errores, y al arrancar la generación se avisa
si falta `nmap`, `hping3`, `iperf` o `scapy` en los hosts. El escaneo
(`nmap`) usa siempre `-Pn` para evitar que un descubrimiento de host
fallido haga que nmap se salte el escaneo entero sin avisar.

Si "scapy" (u otra dependencia) aparece como no encontrada aunque la
instalaste: comprueba la ruta que te da `./venv/bin/pip show scapy`.
Si apunta a `~/.local/lib/pythonX.Y/site-packages` en vez de a
`venv/lib/...`, es una instalación **por usuario**, no dentro del
propio `venv/`. Cuando lo pruebas tú manualmente (`clara`) funciona
porque `$HOME` es `/home/clara`, pero todo el pipeline corre con
`sudo`, y con `sudo` `$HOME` suele pasar a ser `/root` -así que el
Python que corre dentro de Mininet busca en `/root/.local/...` y no lo
encuentra-. Dos capas de arreglo:

1. Reinstala scapy dentro del propio venv (ignorando la copia en
   `~/.local`):
   ```bash
   ./venv/bin/pip install --force-reinstall --no-deps --ignore-installed scapy
   ./venv/bin/pip show scapy   # confirma que ahora apunta a venv/lib/...
   ```
2. `config.py` ahora fija `PYTHONNOUSERSITE=1` como variable de
   entorno nada más importarse (no solo durante la instalación en
   `setup.sh`), así que ningún proceso del pipeline -tampoco los hosts
   de Mininet, que heredan el entorno del proceso que los lanza-
   consultará `~/.local` en tiempo de ejecución, venga o no de una
   instalación por usuario.

Si sigue sin encontrarla, revisa `logs/traffic_generator.log`: ahora
el aviso incluye la salida completa de `python3 -c "import scapy"`
(no solo "no encontrada"), con el error real, el ejecutable exacto
usado y su `sys.path` completo -así no hace falta reproducirlo a mano
para ver por qué falla-.

`setup.sh` ahora también comprueba esto **con sudo** en el propio
paso 5 (las mismas condiciones en las que corre `run_01_dataset.py`, no las
de tu shell normal) y, si falla, reinstala scapy dentro del venv
automáticamente. Si `./setup.sh` ya lo dio por OK pero el aviso sigue
saliendo, prueba exactamente el comando que usa `run_01_dataset.py`:
```bash
sudo env PYTHONNOUSERSITE=1 venv/bin/python3 -c "import sys; print(sys.executable); print(sys.path); import scapy"
```
y pega el error si lo hay.

Si el controlador Ryu no llega a escuchar en el puerto, `run_01_dataset.py`
ya te muestra automáticamente las últimas líneas de
`logs/ryu_controller.log` en la terminal; revisa ahí el motivo real
del fallo (típicamente: `ryu-manager` no instalado en el venv, o
incompatibilidad de `ryu` con tu versión de Python — ver `setup.sh`).

## Por qué el controlador NO filtra los flujos ARP

Puede parecer tentador excluir `eth_type != IP` (ARP, LLDP...) al
escribir el CSV, para "limpiar" filas con `packet_count=0`. **No lo
hagas** si sigues usando el ARP-spoofing tal y como está aquí: la
mitad de la clase `spoofing` (`_arp_spoofing` en
`traffic_generator.py`) es precisamente tráfico ARP -respuestas ARP
falsificadas, capturadas en columnas como `arp_opcode`, `arp_spa`,
`arp_tpa`, `arp_sha`-. Filtrar por `eth_type` borraría esa señal por
completo, no sería un filtro de ruido: sería eliminar la mitad de la
evidencia de esa clase.

Si quieres reducir el ARP "de mantenimiento" (resolución de
direcciones, sin relación con ningún ataque) que pueda quedar en
`scanning`/`ddos`/`normal` -donde ARP no es el mecanismo del ataque,
a diferencia de `spoofing`-, hazlo en el preprocesado, no aquí, para
poder decidirlo con el CSV completo delante y sin perder nada de
forma irreversible en el origen. Por ejemplo, en pandas:
```python
ruido_arp = (df["label"] != "spoofing") & (df["eth_type"] == 2054)
df = df[~ruido_arp]
```

## `MAX_ROWS_PER_PHASE` no se respetaba en `scanning` (dos rondas de arreglo)

**Primera ronda** (con datos de una ejecución de 50.561 filas):
`scanning` acaparaba el 86% del dataset, con fases de hasta **12.152
filas** -8 veces el tope de 1.500-. Causa: el escaneo comprobaba el
tope solo una vez por iteración del bucle (cada 1-3s), pero un único
`nmap -p 1-200 -T5` puede recorrer 200 puertos -200 flujos OpenFlow
distintos- en bien menos de un segundo, y además se iban lanzando
escaneos nuevos sin esperar a que terminaran los anteriores
(solapándose). Se redujeron los rangos de puertos/velocidad, se hizo
secuencial (un escaneo cada vez), y se comprobaba el tope cada 0.3s.

**Segunda ronda** (persistía, más moderado: hasta 2.432 filas, ~60%
por encima del tope): la causa de fondo es que el CSV **solo crece
cuando el controlador sondea** (cada `POLL_INTERVAL`=2s). Por rápido
que se compruebe el tope en el generador, solo puede detectar el
desbordamiento *después* de que el controlador ya haya escrito esas
filas -y aunque se deje de lanzar tráfico nuevo en cuanto se detecta,
los flujos YA CREADOS seguían vivos hasta su `hard_timeout` (15s),
sumando filas de más en cada sondeo restante aunque no se generase
tráfico nuevo. "Dejar de lanzar cosas nuevas" no bastaba.

Arreglo real: el generador ahora puede pedirle al controlador un
**vaciado inmediato** de las tablas de flujo (`FLUSH_REQUEST_FILE`)
en el momento exacto en que detecta el desbordamiento, sin esperar a
que la fase termine y cambie la etiqueta -antes el vaciado solo se
disparaba con cambios de etiqueta-. De paso se acortaron
`FLOW_IDLE_TIMEOUT` (5→3) y `FLOW_HARD_TIMEOUT` (15→10) para reducir
también la "cola" de muestreo de flujos ya inactivos en general, y se
apretó un poco más el rango de puertos del escaneo (1-40 → 1-20).

**Tercera ronda** (con el dataset final de 30.000 filas): también se
detectó `normal` desbordando el tope (1.957 filas en una sola fase).
Causa: `normal_traffic` era la única fase que no usaba la comprobación
fina de `_sleep_with_cap` (cada 0.3s) que ya tenían `ddos`/`spoofing`/
`scanning` -seguía comprobando el tope solo una vez por iteración del
bucle, con una pausa de 1-3s sin comprobar nada en medio-. Ya usa el
mismo mecanismo que el resto.

**Nota sobre cómo verificar esto tú mismo**: si agrupas el CSV por
bloques de etiqueta consecutiva para comprobar el tope por fase, ten
cuidado -si el generador elige la MISMA fase varias veces seguidas por
azar (25% de probabilidad cada vez, con 4 fases), tu agrupación las
juntará en un solo bloque aunque sean varias fases distintas, cada una
bien dentro del tope. La forma de distinguir un desbordamiento real de
este "falso positivo": ningún bloque genuino de una sola fase puede
durar más que `MAX_PHASE_DURATION` (25s por defecto); si un bloque
dura más que eso, son varias fases seguidas fusionadas por tu análisis,
no un fallo del generador.

## La etiqueta `warmup` (nueva)

El `pingAll()` inicial (240 pares de hosts) ya no se etiqueta como
`normal`, sino como `warmup`. Es tráfico benigno igualmente, pero muy
homogéneo (240 conexiones casi idénticas de 1-2 paquetes cada una) y,
en una ejecución real, llegó a ser el **88.6% de todas las filas
`normal`** cuando la primera fase elegida al azar también resultó ser
`normal` -diluyendo la variedad que sí aporta `normal_traffic()`
(ping/iperf TCP/UDP variados)-. Con etiqueta propia, tú decides en el
preprocesado: inclúyela como `normal` más (`df["label"].replace("warmup", "normal")`)
si te interesa ese volumen, o fuera del dataset de entrenamiento
(`df = df[df["label"] != "warmup"]`) si prefieres que `normal`
represente solo la variedad diseñada -esto último es lo recomendado:
es reversible y queda documentado en tu preprocesado qué excluiste y
por qué, mejor metodológicamente que no generarlo directamente-.

Si aun así prefieres que esas filas ni se lleguen a escribir en el
CSV, pon `WRITE_WARMUP_ROWS = False` en `config.py`.

## Cuánto target_rows/total_duration usar, en general

Lo que ya hace el pipeline (`TARGET_ROWS` como criterio de parada real,
`TOTAL_DURATION` como techo de seguridad) es el enfoque habitual: se
fija el **tamaño del dataset que necesitas para el modelo**, no cuánto
tiempo estás dispuesto a esperar, y se deja que la duración salga sola.

Recomendación para la ejecución **final** (no de prueba), pensada
para entrenar Logistic Regression, Decision Tree y Random Forest -los
tres son modelos clásicos, no necesitan volúmenes de deep learning-,
con las tres capas de MAX_ROWS_PER_PHASE ya validadas y un balance
entre clases estable: `TARGET_ROWS = 30000` y `TOTAL_DURATION = 4500`
como techo de seguridad -con el ritmo típico (~8 filas/s, incluyendo
`warmup`) son unos 60-65 min de generación real, con margen de sobra
en el techo-. Tras quitar `warmup` (~3.500-4.000 filas típico) quedan
del orden de **~26.000 filas reales** (~6.500 por clase de media): de
sobra para que Random Forest generalice bien y para un split
train/test (o validación cruzada) con métricas estables en los tres
modelos. Ir más allá no aporta gran cosa con estos algoritmos
concretos -el techo de rendimiento con LR/DT/RF sobre datos tabulares
de este tipo se alcanza mucho antes que con deep learning-.

Sobre el balance entre clases: no hace falta perseguir un 25%/25%/25%/25%
exacto -con selección aleatoria de fases varía de una ejecución a
otra-, pero si al terminar ves una clase muy por debajo de las demás,
puedes compensarlo en el preprocesado (`class_weight` en el modelo,
sobremuestreo tipo SMOTE en la clase minoritaria, o submuestreo de la
mayoritaria) en vez de perseguir el balance perfecto en la generación.

## Preprocesado, entrenamiento y evaluación (`ml/`)

Con el CSV ya generado, `ml/` contiene el pipeline completo para
entrenar y comparar Logistic Regression, Decision Tree y Random
Forest. Se ejecuta con el mismo `venv/` (sus dependencias —
`scikit-learn`, `pandas`, `numpy`, `matplotlib`, `joblib` — están
declaradas en `setup.py` junto a las de la generación), pero **sin
`sudo`**: trabaja sobre un CSV estático, no toca Mininet.

```bash
venv/bin/python3 ml/run_02_ml.py
```

(o paso a paso: `ml/preprocessing.py`, `ml/train.py`, `ml/evaluate.py`
por separado, si quieres depurar cada fase por su cuenta)

### `ml/preprocessing.py`

1. **Características de ventana temporal** (ver más abajo).
2. **Quita las filas `warmup`** (no representan ninguna de las 4
   clases a clasificar).
3. **Quita duplicados.**
4. **Elimina identificadores rígidos**: `timestamp`, IPs, MACs y
   `dpid` -con solo 16 hosts y 5 switches en el laboratorio, el
   modelo podría memorizar qué IP/MAC concreta aparece en qué clase
   en vez de aprender patrones de tráfico generalizables-.
5. **Elimina columnas constantes** (`idle_timeout`/`hard_timeout`):
   mismo valor en TODAS las filas del dataset -comprobado, no
   asumido-, cero información posible.
6. **Filtra nulos/infinitos de las métricas derivadas**
   (`packet_count_per_second`, `byte_count_per_second`,
   `avg_packet_size`). Distinto del NaN *estructural* de puertos/ARP
   (un flujo UDP no tiene `tcp_dst_port`) -eso no es un dato perdido,
   se rellena con 0 en vez de eliminar la fila-.
7. **Codificación numérica de categóricas** (`eth_type`, `ip_proto`,
   `arp_opcode`) con `LabelEncoder`.
8. **Reconstruye a qué FASE pertenece cada fila** (`groups`, ver
   siguiente apartado) -imprescindible para evaluar bien-.

Guarda en `data/processed/` el dataset completo ya limpio (`X.csv`,
`y.npy`, `groups.npy`) y en `models/` los artefactos de codificación
(`le_y.pkl`, `encoders.pkl`). **Ya NO hace el split train/test, ni
escala, ni selecciona características aquí** -motivo explicado abajo-.

**El balanceo de clases NO se hace aquí.** Nada de sobremuestreo ni
submuestreo. Se resuelve en `ml/train.py` con `class_weight="balanced"`
en los tres modelos: una solución algorítmica integrada en
scikit-learn, no una manipulación de los datos.

### Por qué el split train/test cambió de "aleatorio por fila" a "por fase completa" (GroupKFold)

Un ataque concreto (una "fase" de `traffic_generator.py`) dura
10-25s, y el controlador muestrea la tabla de flujos cada 2s mientras
está activo -así que ESE MISMO ataque genera varias filas en el CSV,
todas muy parecidas entre sí (mismo atacante, misma víctima, mismo
tipo de ataque, segundos de diferencia-.

Con un split aleatorio por fila (`train_test_split` de toda la vida),
filas "gemelas" de la MISMA fase podían acabar repartidas entre train
y test. El modelo no estaba aprendiendo a reconocer un ataque de un
tipo dado en general -estaba parcialmente memorizando fragmentos de
ataques concretos que ya había visto en parte durante el
entrenamiento, y luego se "examinaba" con fragmentos casi idénticos
del mismo ataque-. Eso infla el F1 medido de forma artificial: no mide
qué tan bien generalizaría el modelo a un ataque **nuevo**, mide qué
tan bien reconoce fragmentos de ataques que, en la práctica, ya vio.

**Comprobado empíricamente, no solo en teoría**: con split aleatorio
por fila, el F1 (macro) de Random Forest salía en **0.777**. Split
por fase completa (ninguna fase repartida entre train y test):
**~0.46**. La diferencia es demasiado grande para ignorarla.

Un único split por fase (un solo 80/20), además, es muy inestable:
probado con 5 semillas distintas, el F1 osciló entre 0.38 y 0.60 según
qué fases en concreto caían en el test -pocas fases (159 reconstruidas
en este dataset) hacen que un solo split dependa mucho del azar-. Por
eso se usa **`GroupKFold`** (5 particiones) en vez de un único split:
se promedia el resultado de varias particiones distintas, dando una
estimación más estable Y sin la fuga de información entre fases.

**Consecuencia práctica en el código**: el escalado (`StandardScaler`)
y la selección de características por importancia (Random Forest) ya
NO se hacen una vez en `preprocessing.py` -eso volvería a filtrar
información entre fases de train y test, por la puerta de atrás-. Se
hacen DENTRO de cada fold de la validación cruzada, en
`ml/evaluate.py`, ajustados solo con los datos de entrenamiento de
ESE fold.

**¿Y por qué no bajar directamente el F1 a 0.46 y ya está?** Porque
ese número concreto es poco fiable por sí solo (mucha variedad entre
folds: ±0.086 de desviación típica) y porque el split aleatorio por
fila, aunque optimista, no es una práctica inventada por nosotros -es
la más habitual en la literatura de detección de intrusiones con ML
(incluso con datasets de referencia como NSL-KDD o CICIDS2017)-. Lo
correcto es reportar la validación cruzada agrupada como medida
principal y honesta de generalización (que es lo que hace ahora el
pipeline), documentando claramente el porqué -que es precisamente lo
que se ha hecho aquí-.

**Qué ayudaría a que el modelo generalizase mejor a variantes de
ataque nuevas** (probado, no solo intuido): regularizar el modelo
(limitar la profundidad de los árboles) apenas cambia nada
(0.458 → 0.462 de F1 en una prueba con Random Forest) -no es un
problema de sobreajuste a ruido que se arregle con hiperparámetros-.
Lo que sí ayudaría de verdad es tener **más fases distintas de cada
tipo de ataque** (más episodios, no solo más filas dentro de los
mismos episodios) y **más variedad de parámetros** dentro de cada
tipo (más combinaciones de flags de `nmap`/`hping3`, no solo
repeticiones de las mismas variantes) -ambas cosas requieren volver a
generar el dataset con más duración/variedad, una decisión de tiempo
que queda fuera del alcance de esta fase-.

### `tcp_flags` (nueva, en `sdn_monitor.py`, no en `ml/`)

**Nota histórica**: `_start_bg` escribía en `logs/traffic_generator.log`
con `>` (sobrescribir) en vez de `>>` (añadir) -bug ya corregido-, lo
que borraba todo el historial de la tirada cada vez que se lanzaba un
comando en segundo plano. Corregido a `>>`, y además `generate_dataset()`
(en `traffic_generator.py`) vacía `logs/traffic_generator.log` al
empezar cada tirada automáticamente -no hace falta borrarlo a mano-,
para que el log de cada tirada quede aislado y no se mezcle con el de
tiradas anteriores. (`logs/ryu_controller.log` ya se sobrescribía solo
desde el principio, vía `run_01_dataset.py`.)

A diferencia de las features de ventana temporal (calculadas offline
en `preprocessing.py` sobre el CSV ya generado), esta se captura en
**el propio generador**: `_packet_in_handler` ve el paquete completo
del PRIMER paquete de cada flujo nuevo (antes de instalar la regla),
algo que ya recibía pero del que solo se aprovechaban IPs/puertos. Se
guarda `tcp_pkt.bits` (flags SYN/ACK/FIN/RST/...) en un diccionario
nuevo (`pending_tcp_flags`, mismo patrón que `pending_offsets`) y se
escribe en el CSV en cada sondeo mientras el flujo viva.

Por qué en el generador y no en preprocessing (a diferencia de las
features de ventana): esta información NO EXISTE en el CSV actual -no
es un cálculo derivable de columnas ya guardadas, hace falta capturarla
en el momento en que el controlador ve el paquete real-. Requiere
regenerar el dataset para tener efecto.

Motivación: una sonda ACK suelta (ver más abajo, en `scanning`) manda
un paquete ACK sin conexión previa como primer paquete de un flujo
-algo que una conexión legítima o un SYN scan prácticamente nunca
hacen-. Es una señal estructural nueva, no otra variante de las que ya
había.

`tcp_flags` se trata como categórica (`LabelEncoder`, combinaciones de
bits concretas son categorías distintas, no una escala) y como NaN
estructural (vacío en flujos ARP/UDP/ICMP, mismo criterio que
`tcp_src_port`).

Confirmado con pruebas reales (5.000-30.000 filas): SYN y RST+ACK se
capturan con normalidad y dan señal real para distinguir `scanning`,
algo que antes no existía.

### Características de ventana temporal

Además de las columnas propias de cada fila, se calculan 4
características de *patrón entre flujos* con una ventana deslizante de
5s hacia atrás (nunca mira al futuro, sin fuga de información):
`distinct_ports_by_src_5s` (puertos distintos tocados por el mismo
origen -escaneo de puertos-), `distinct_targets_by_src_5s` (destinos
distintos tocados por el mismo origen -escaneo de red-),
`flows_to_target_5s` (flujos hacia el mismo destino) y
`distinct_sources_to_target_5s` (orígenes distintos hacia el mismo
destino -DDoS distribuido-). Usan `ip_src`/`ip_dst`/`timestamp` solo
como cálculo intermedio -se descartan después como siempre-.

Se calculan con `feature_windows.WindowTracker` (raíz del proyecto),
un módulo **compartido**: aquí se usa en modo lote, y la misma clase
se reutilizará sin cambios cuando se aborde la fase de detección en
vivo, alimentada evento a evento desde `sdn_monitor.py` -evitando
*training-serving skew*-. Se calculan en `preprocessing.py`
("offline") y no en el generador SDN porque no hace falta regenerar
el dataset de Mininet/Ryu para iterar sobre esto.

**Pendiente para cuando se conecte a `sdn_monitor.py`**: alimentar
`WindowTracker` con la MISMA granularidad de evento que usa el CSV de
entrenamiento (una llamada por sondeo del controlador, no por
paquete) -ver detalle en el propio código de `preprocessing.py`-.

Impacto medido con la metodología de evaluación correcta
(`GroupKFold`, comprobado, no estimado): sin estas 4 características,
Random Forest da F1 = 0.4225 ± 0.074; con ellas, sube a 0.4661 ± 0.086.
Una mejora real (+0.044) que se mantiene bajo la evaluación honesta
-más modesta que la mejora que parecía haber bajo el split aleatorio
por fila (que llegaba a sugerir +0.05), pero genuina-.

### `ml/train.py`

Ajusta el pipeline **final desplegable** (escalado + selección de
características + modelo) sobre **todo** el dataset disponible -no
sobre un 80%-. Este script no mide rendimiento (eso lo hace
`evaluate.py` con `GroupKFold`); solo produce el modelo que se
guardaría para usar de verdad, y para eso conviene aprovechar todos
los datos históricos disponibles, no reservarse un 20% sin usar.
`class_weight="balanced"` en los tres modelos, midiendo el tiempo de
entrenamiento de cada uno (para la tabla de coste computacional).

### `ml/evaluate.py`

Evalúa con `GroupKFold` (5 particiones, agrupadas por fase) y genera:

1. **Tabla + gráfico de barras** con Accuracy/Precision/Recall/F1
   (media entre folds, más la desviación típica del F1 entre folds)
   (`results/tables/metrics_comparison.csv`,
   `results/figures/metrics_comparison.png`). Mejor modelo por F1
   medio, guardado como `models/best_model.pkl`.
2. **Matrices de confusión**: un PNG por modelo, construidas con las
   predicciones *out-of-fold* (cada fila predicha exactamente una vez,
   por un modelo que nunca vio su propia fase durante el
   entrenamiento) (`results/figures/confusion_matrix_<modelo>.png`).
3. **Tabla de coste computacional**: tiempo de entrenamiento del
   modelo final (de `train.py`, sobre todo el dataset) y tiempo de
   inferencia por flujo en ms (medido aquí, promediado entre folds)
   (`results/tables/computational_cost.csv`).

Precision/Recall/F1 con promedio **macro** (todas las clases pesan
igual) -coherente con `class_weight="balanced"`-.

### Resultado con el dataset real (30.097 filas → 28.360 tras limpiar, 158 fases)

| Modelo | Accuracy | F1 (macro, media GroupKFold) | Desv. típica F1 | Entrenamiento | Inferencia |
|---|---|---|---|---|---|
| Logistic Regression | 0.399 | 0.382 | ±0.054 | 0.19s | 0.0003 ms/flujo |
| Decision Tree | 0.442 | 0.418 | ±0.069 | 0.18s | 0.0004 ms/flujo |
| **Random Forest** | **0.489** | **0.466** | ±0.086 | 6.65s | 0.033 ms/flujo |

Random Forest sigue siendo el mejor de los tres, aunque con un margen
más ajustado sobre Decision Tree que con la evaluación anterior (0.466
frente a 0.418, no 0.777 frente a 0.729). Esto es esperable y
coherente: la evaluación agrupada mide algo más difícil (generalizar a
fases enteras nunca vistas), así que las diferencias entre modelos se
comprimen un poco. La desviación típica entre folds (0.054-0.086)
también es un dato honesto a incluir en la memoria: refleja cuánto
varía el rendimiento según qué fases en concreto se usan para
entrenar, no un número inventado.
