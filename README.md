# Decrypter Master Worker

Sistema distribuido para buscar una clave secreta RIPv2 autenticada mediante fuerza bruta, coordinado por un master y varios workers TCP. El proyecto lee un archivo PCAP, extrae un digest MD5 asociado a un paquete RIPv2 autenticado y reparte rangos del espacio de claves entre nodos para encontrar la clave correcta.

## 1. Requisitos

- Python 3.10 o superior
- Un archivo PCAP compatible con el formato esperado en la carpeta `pcaps/`
- Una red donde el master pueda escuchar conexiones TCP y los workers puedan conectarse a ese host:puerto

## 2. Estructura esperada del proyecto

```text
Decrypter_Master_Worker/
├── master.py
├── worker.py
├── README.md
└── pcaps/
    ├── rip_passkey_size_06_01.pcap
    ├── rip_passkey_size_06_02.pcap
    ├── rip_passkey_size_07_01.pcap
    └── rip_passkey_size_07_03.pcap
```

Los nombres de archivo deben seguir exactamente este patrón:

```text
rip_passkey_size_xx_yy.pcap
```

Donde:
- `xx` = longitud de la clave (por ejemplo, `06`, `07`, `08`)
- `yy` = identificador del archivo para ese tamaño de clave (por ejemplo, `01`, `02`, `03`)

## 3. Guía rápida de uso

### 3.1 Arrancar el master

Desde la carpeta del proyecto:

```bash
python master.py --key-length 7 --id 03 --host 0.0.0.0 --port 5000
```

Parámetros:
- `--key-length`: longitud de la clave a buscar. Obligatorio.
- `--id`: identificador del PCAP. Obligatorio.
- `--host`: interfaz de escucha del master. Por defecto `0.0.0.0`.
- `--port`: puerto TCP del master. Por defecto `5000`.
- `--timeout`: timeout por tarea antes de reencolarla. Por defecto `60.0` segundos.
- `--num-bloques`: número de bloques iniciales del espacio de búsqueda. Por defecto `1000`.

El master:
- localiza el PCAP automáticamente como `pcaps/rip_passkey_size_07_03.pcap`
- Parsea el paquete RIP del PCAP
- Calcula el espacio total de búsqueda: `BASE ^ key_length`
- Inicia la búsqueda de inmediato, sin esperar a que todos los workers se conecten
- Acepta workers dinámicamente mientras corre

### 3.2 Conectar workers

En una máquina distinta o en la misma, ejecuta:

```bash
python worker.py --host 192.168.1.50 --port 5000
```

El worker se conecta al master y queda esperando tareas del tipo `task` hasta que recibe un `done` o la conexión se cierra.

### 3.3 Ejemplo de flujo completo

Terminal 1 (master):

```bash
python master.py --key-length 7 --id 03 --host 0.0.0.0 --port 5000
```

Terminal 2 (worker 1):

```bash
python worker.py --host 127.0.0.1 --port 5000
```

Terminal 3 (worker 2):

```bash
python worker.py --host 127.0.0.1 --port 5000
```

El master empieza a repartir rangos y cada worker devuelve el resultado de la tarea y su velocidad en H/s.

## 4. Protocolo de coordinación TCP, tipos de mensaje y particionamiento del espacio de claves

### 4.1 Modelo de comunicación

La coordinación usa sockets TCP con mensajes JSON delimitados por salto de línea (`\n`).

Cada mensaje se serializa con:

```python
json.dumps(obj) + "\n"
```

y se recibe con:

```python
recv_message(sock)
```

que acumula bytes hasta encontrar un `\n` y luego hace `json.loads(...)`.

### 4.2 Tipos de mensaje

#### Mensaje del master a worker (tarea)

```json
{
  "cmd": "task",
  "id_tarea": 12,
  "mensaje": "<hex del paquete RIP sin los 16 bytes finales>",
  "hash": "<digest md5 esperado>",
  "inicio": 0,
  "fin": 1000000,
  "key_length": 7
}
```

Campos:
- `cmd`: indica que es una tarea de trabajo
- `id_tarea`: identificador único del bloque asignado
- `mensaje`: payload RIP en hexadecimal, sin los 16 bytes finales del digest autenticado
- `hash`: digest MD5 esperado a comparar
- `inicio` y `fin`: rango de la clave a evaluar en el espacio de búsqueda
- `key_length`: longitud de la clave buscada

#### Respuesta del worker al master

```json
{
  "id_tarea": 12,
  "resultado": "abc1234",
  "tiempo_segundos": 1.83,
  "hashes_por_segundo": 1200000.0
}
```

Campos:
- `id_tarea`: identificador de la tarea completada
- `resultado`: clave si fue encontrada; `null` si no estaba en ese bloque
- `tiempo_segundos`: tiempo de ejecución del rango
- `hashes_por_segundo`: rendimiento del nodo en H/s para esa tarea

#### Señal de cierre

```json
{"cmd": "done"}
```

Cuando la tarea termina o el master cierra la sesión, manda `done` para que el worker salga del ciclo.

### 4.3 Particionamiento del espacio de claves

El alfabeto es:

```python
string.ascii_lowercase + string.digits
```

Esto produce 36 caracteres posibles:
- `a-z` → 26 caracteres
- `0-9` → 10 caracteres

El espacio total para una clave de longitud `L` es:

```text
36^L
```

El master crea una cola y la divide en bloques usando:

```python
total_combinaciones = BASE ** key_length
bloque = total_combinaciones // num_bloques
```

Cada bloque tiene un `[inicio, fin)` y se convierte en una tarea. Por ejemplo, para `key_length = 7`:

```text
36^7 = 78,364,164,096 combinaciones
```

El master entonces reparte esos bloques a workers en tiempo real. La búsqueda no depende de que exista un número fijo de workers al inicio; la cola puede ser atendida por quien llegue primero, y el supervisor reencola tareas que no terminan a tiempo.

### 4.4 Estrategia de ejecución del master

El master corre dos motores simultáneamente:
- un hilo local para procesar tareas localmente
- un hilo por cada worker remoto que conecte

Esto permite que:
- el master comience de inmediato
- los workers puedan sumarse dinámicamente
- la búsqueda siga corriendo aunque un nodo tarde o se caiga

## 5. Ingeniería inversa y validación de la estructura del paquete RIP en bruto y el cálculo del HMAC

### 5.1 Cómo se inspecciona el PCAP

El parser recorre la captura capa por capa:
- Ethernet
- IP
- UDP
- paquete RIP

La lógica principal es:

```python
if len(pkt_data) < 42 or pkt_data[12:14] != b"\x08\x00":
    continue
```

Esto valida que la trama sea Ethernet con protocolo IPv4.

Luego revisa:

```python
if ip_header[9] != 17:
    continue
```

para confirmar que el protocolo es UDP.

Después identifica el puerto destino:

```python
dest_port = struct.unpack(">H", udp_header[2:4])[0]
if dest_port == 520:
```

Esto detecta un paquete RIP, porque RIPv2 usa UDP/520.

### 5.2 Cómo se valida el payload RIP autenticado

Cuando ya encuentra un paquete RIP, valida:

```python
if len(rip_payload) >= 36 and rip_payload[0] == 2 and rip_payload[1] == 2:
```

Esto significa:
- `rip_payload[0] == 2` → comando `response`
- `rip_payload[1] == 2` → versión RIPv2

La estrategia del proyecto asume que el último bloque de 16 bytes del payload es el digest de autenticación y que el resto del payload representa el mensaje RIP original:

```python
mensaje_rip = rip_payload[:-16]
hash_real = rip_payload[-16:].hex()
```

Esto se valida en la práctica con la comparación de hash en la función:

```python
def calcular_hash_rfc2082(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    clave_padded = clave_bytes.ljust(16, b"\x00")
    buffer_completo = mensaje_bytes + clave_padded
    return hashlib.md5(buffer_completo).hexdigest()
```

### 5.3 Cómo se calcula el HMAC / digest de la clave

La implementación sigue un patrón equivalente al RFC 2082 clásico para autenticación RIP:

```text
MD5(mensaje_rip + clave_padded_a_16_bytes)
```

Donde:
- `mensaje_rip` = bytes del bloque RIP sin el digest final
- `clave_padded_a_16_bytes` = la clave candidata, rellenada con `\x00` hasta 16 bytes

La comparación final es:

```python
if calcular_hash_rfc2082(mensaje_rip_bytes, clave_bytes) == hash_real:
```

Es decir, el sistema busca la clave candidata que produce el mismo MD5 que el digest extraído del PCAP.

### 5.4 Validación de la hipótesis

La validación consiste en dos pasos:
1. Confirmar que el PCAP porte un paquete UDP/520 con formato RIPv2 (`command=2`, `version=2`).
2. Verificar que el último bloque de 16 bytes coincide con el digest producido al recalcular MD5 con cada clave candidata.

Este enfoque permite confirmar que la autenticación no usa una variante totalmente distinta; más bien se trata de una firma MD5 sobre el paquete RIP, con el valor de la clave rellenado a 16 bytes como dato complementario.

## 6. Métricas de referencia y evaluación del cuello de botella

La implementación mide dos métricas clave:
- HPS por tarea (`hashes_por_segundo`)
- HPS colectivo del cluster (promedio del total de hashes evaluados dividido por el tiempo total)

### 6.1 Rendimiento por nodo

Cada worker reporta:

```python
rate_individual = total_evaluaciones / t_transcurrido
```

y el master registra esto en el log:

```text
[WORKER] Tarea #12 finalizada en 1.83s | Rendimiento Individual: 1,200,000 H/s
```

Ejemplo de referencia:

| Nodo | Tipo | HPS observado |
|------|------|---------------|
| Worker-01 | Ryzen 7 5800X | 1,200,000 H/s |
| Worker-02 | Intel i5-12400 | 890,000 H/s |
| Worker-03 | Raspberry Pi 4 | 135,000 H/s |

### 6.2 Rendimiento colectivo del clúster

El master calcula:

```python
rate_colectivo = hashes_evaluados / tiempo_total
```

y muestra:

```text
Rendimiento Colectivo Red: 2,225,000 H/s (Hashes/segundo)
```

Ejemplo orientativo:

| Configuración | HPS total |
|---------------|-----------|
| 1 worker potente | 1.2 M H/s |
| 3 workers heterogéneos | 2.2 M H/s |
| 5 workers de gama media | 4.1 M H/s |

### 6.3 Cómo interpretar si la carga está limitada por CPU o por socket/red

La regla práctica es:
- Si la CPU está al 100% en todos los nodos y el HPS por worker es estable, la limitación es computacional.
- Si el HPS cae aunque la CPU no esté saturada, la limitación más probable es de red o de latencia del socket.
- Si el master está continuamente reencolando tareas y la red se llena de respuestas lentas, el sistema está limitado por el transporte o por la espera de respuesta del nodo.

En esta implementación, la métrica `hashes_por_segundo` se usa como criterio de diagnóstico del cuello de botella. Si el rendimiento de la red está por debajo del rendimiento del CPU local, se puede inferir procesamiento suficientemente intenso como para que el socket haya empezado a limitar el flujo de tareas.

## 7. Detección de muerte de un nodo y garantía de no perder bloques

### 7.1 Detección de nodo muerto

El sistema no usa heartbeats periódicos; usa dos mecanismos de detección implicita:

1. Desconexión abrupta del socket:
   ```python
   if respuesta is None:
       raise ConnectionError("Worker desconectado.")
   ```

2. Timeout de tarea:
   ```python
   if ahora - timestamp > timeout_segundos:
       tareas_expiradas.append(id_tarea)
   ```

El `supervisor_tareas` supervisa las tareas en progreso y, si una no termina en el tiempo configurado, la reencola automáticamente.

### 7.2 Cómo se garantiza que ningún bloque quede sin procesar

El flujo es:
- Cuando la tarea sale de la cola, se registra en `tareas_en_progreso` bajo un lock.
- El worker recibe la tarea y la ejecuta.
- Si el worker responde bien, se elimina de `tareas_en_progreso` y se marca completada.
- Si falla la conexión o la tarea excede el timeout, la tarea se vuelve a poner en la cola.

El código hace esto exactamente:

```python
with lock_tareas:
    if id_tarea in tareas_en_progreso:
        tareas_en_progreso.pop(id_tarea, None)
        cola_tareas.put(tarea)
```

Y también en el supervisor:

```python
for id_tarea in tareas_expiradas:
    tarea, _ = tareas_en_progreso.pop(id_tarea)
    cola_tareas.put(tarea)
```

Esto garantiza que no se pierda un bloque por un worker caído o lento. El único caso en que un bloque no termina es si la búsqueda completa acaba sin encontrar la clave o si el programa termina por corte externo.

## 8. Notas finales

- El master no espera a que todos los workers existan antes de iniciar la búsqueda.
- Los workers pueden conectarse en cualquier momento.
- La búsqueda es distribuida, tolerante al fallo y reencola tareas lentas o caídas.
- El PCAP a usar debe existir bajo `pcaps/` con el nombre exacto `rip_passkey_size_xx_yy.pcap`.

## 9. Ejemplo de ejecución real

```bash
python master.py --key-length 7 --id 03 --host 0.0.0.0 --port 5000
python worker.py --host 192.168.1.50 --port 5000
python worker.py --host 192.168.1.51 --port 5000
```

El master localizará automáticamente este archivo:

```text
./pcaps/rip_passkey_size_07_03.pcap
```

y comenzará a repartir trabajo por rangos, sin necesidad de que los workers estén presentes al momento del arranque.
