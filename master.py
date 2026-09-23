import hashlib
import hmac
import json
import socket
import threading
import queue
import time

from extraer_pcap import extraer_pares

# Configuración global / Constantes de red
HOST = '0.0.0.0'  # escucha en todas las interfaces de red, no solo localhost
PORT = 65432

# Configuración del espacio de búsqueda
ALFABETO = "abcdefghijklmnopqrstuvwxyz0123456789"  # minúsculas + dígitos
LONGITUDES = [6]  # clave conocida de 6 caracteres (cambia a [6,7,8] etc. si quieres variar)

# Configuración de chunking / heartbeat
CHUNK_SIZE = 5_000_000        # tamaño de cada "pedazo" de trabajo
HEARTBEAT_TIMEOUT = 10.0      # segundos sin noticias del worker -> se considera muerto


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


class GestorChunks:
    """
    Genera chunks de forma perezosa, recorriendo cada longitud de clave
    (ej. 6, luego 7, luego 8 caracteres) como un "segmento" independiente
    del espacio de búsqueda total.
    """
    def __init__(self, longitudes: list[int], tam_alfabeto: int, chunk_size: int):
        self.chunk_size = chunk_size
        self.segmentos = [(longitud, tam_alfabeto ** longitud) for longitud in longitudes]
        self.indice_segmento = 0
        self.siguiente_inicio = 0
        self.lock = threading.Lock()
        self.reintentos = queue.Queue()  # chunks que fallaron y hay que reasignar

    def total_combinaciones(self) -> int:
        return sum(tam for _, tam in self.segmentos)

    def total_chunks_estimado(self) -> int:
        return sum(-(-tam // self.chunk_size) for _, tam in self.segmentos)

    def obtener_chunk(self):
        # Prioridad: chunks que quedaron pendientes por un worker caído
        try:
            return self.reintentos.get_nowait()
        except queue.Empty:
            pass

        with self.lock:
            while self.indice_segmento < len(self.segmentos):
                longitud, tam_segmento = self.segmentos[self.indice_segmento]
                if self.siguiente_inicio >= tam_segmento:
                    # Este segmento (esta longitud) ya se agotó, pasar al siguiente
                    self.indice_segmento += 1
                    self.siguiente_inicio = 0
                    continue
                inicio = self.siguiente_inicio
                fin = min(inicio + self.chunk_size, tam_segmento)
                self.siguiente_inicio = fin
                return (longitud, inicio, fin)
            return None

    def reencolar(self, chunk: tuple[int, int, int]) -> None:
        self.reintentos.put(chunk)

    def esta_vacio(self) -> bool:
        with self.lock:
            agotado = self.indice_segmento >= len(self.segmentos)
        return agotado and self.reintentos.empty()


def enviar_json(conn: socket.socket, obj: dict) -> None:
    """Manda un mensaje JSON delimitado por salto de línea."""
    conn.sendall((json.dumps(obj) + "\n").encode('utf-8'))


def leer_lineas(conn: socket.socket, buffer: bytearray):
    """Generador que va leyendo del socket y produciendo líneas JSON completas."""
    while True:
        while b"\n" in buffer:
            linea, _, resto = buffer.partition(b"\n")
            buffer.clear()
            buffer.extend(resto)
            if linea.strip():
                yield json.loads(linea.decode('utf-8'))
        try:
            data = conn.recv(4096)
        except socket.timeout:
            yield None  # señal de "no hubo heartbeat a tiempo"
            continue
        if not data:
            return  # conexión cerrada
        buffer.extend(data)


def verificar_candidato(clave_str: str, pares: list[dict]) -> tuple[bool, int, int]:
    """
    Re-calcula el HMAC-MD5 de la clave candidata contra TODOS los pares
    mensaje/hash extraídos del pcap (misma keyid = misma clave secreta).
    Regresa (es_valida_en_todos, coincidencias, total_pares).
    """
    coincidencias = 0
    clave_bytes = clave_str.encode('utf-8')
    for par in pares:
        mensaje_bytes = bytes.fromhex(par["mensaje_hex"])
        if calcular_hash_hmac(mensaje_bytes, clave_bytes) == par["hash_real"]:
            coincidencias += 1
    return (coincidencias == len(pares), coincidencias, len(pares))


def manejar_worker(
    conn: socket.socket,
    addr: tuple[str, int],
    mensaje_rip_hex: str,
    hash_real: str,
    gestor: GestorChunks,
    evento_hallado: threading.Event,
    resultados: dict,
    pares_verificacion: list[dict]
) -> None:
    print(f"[MASTER] Conectado con Worker en {addr}")
    conn.settimeout(HEARTBEAT_TIMEOUT)
    buffer = bytearray()
    lector = leer_lineas(conn, buffer)

    chunk_actual = None
    try:
        while not evento_hallado.is_set():
            # Asignar un nuevo chunk si el worker no tiene uno pendiente
            if chunk_actual is None:
                chunk_actual = gestor.obtener_chunk()
                if chunk_actual is None:
                    enviar_json(conn, {"tipo": "sin_trabajo"})
                    break

                longitud, inicio, fin = chunk_actual
                enviar_json(conn, {
                    "tipo": "tarea",
                    "mensaje": mensaje_rip_hex,
                    "hash": hash_real,
                    "longitud": longitud,
                    "inicio": inicio,
                    "fin": fin
                })
                print(f"[MASTER] -> {addr} longitud={longitud} chunk [{inicio}:{fin}]")

            # Esperar heartbeat o resultado (con timeout ya puesto en el socket)
            try:
                msg = next(lector)
            except StopIteration:
                # El worker cerró la conexión sin avisar
                print(f"[MASTER] Worker {addr} desconectado abruptamente.")
                break

            if msg is None:
                # Timeout: no llegó nada en HEARTBEAT_TIMEOUT segundos
                print(f"[MASTER] Worker {addr} no respondió a tiempo. Reencolando chunk {chunk_actual}.")
                gestor.reencolar(chunk_actual)
                break

            tipo = msg.get("tipo")

            if tipo == "heartbeat":
                # El heartbeat solo sirve para resetear el timeout del socket;
                # no se imprime para no saturar la terminal.
                continue  # seguir esperando en el mismo chunk

            if tipo == "chunk_terminado":
                resultado = msg.get("resultado")
                if resultado:
                    es_valida, coincidencias, total = verificar_candidato(resultado, pares_verificacion)
                    if es_valida:
                        resultados['clave'] = resultado
                        print(f"\n[MASTER] ¡Clave encontrada y VERIFICADA por {addr}: '{resultado}' "
                              f"({coincidencias}/{total} paquetes coinciden)!")
                        evento_hallado.set()
                        break
                    else:
                        # Coincidencia solo en el hash "objetivo" (o colisión rarísima),
                        # pero falla contra los demás paquetes -- se descarta y se sigue.
                        print(f"[MASTER] Candidato '{resultado}' de {addr} NO pasó la verificación "
                              f"cruzada ({coincidencias}/{total}). Descartado, se continúa buscando.")
                        chunk_actual = None
                        continue
                else:
                    chunk_actual = None  # pedir el siguiente chunk
                    continue

    except Exception as e:
        print(f"[MASTER] Error con Worker {addr}: {e}")
        if chunk_actual is not None:
            gestor.reencolar(chunk_actual)  # no perder el trabajo pendiente
    finally:
        conn.close()


def cola_chunks_vacia_y_sin_hilos_activos(gestor: GestorChunks, hilos: list[threading.Thread]) -> bool:
    return gestor.esta_vacio() and bool(hilos) and all(not h.is_alive() for h in hilos)


def obtener_ip_local() -> str:
    """Intenta obtener la IP local (LAN) del equipo, para mostrarla al usuario."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))  # no manda datos reales, solo fuerza a elegir la interfaz de salida
            return s.getsockname()[0]
    except Exception:
        return "desconocida (revisa 'ip addr' / 'ipconfig')"


def iniciar_master() -> None:
    RUTA_PCAP = "rip_passkey_size_06_01.pcap"

    pares = extraer_pares(RUTA_PCAP)
    if not pares:
        print(f"[MASTER] No se encontraron paquetes RIP con autenticación MD5 en '{RUTA_PCAP}'.")
        return

    print(f"[MASTER] Se extrajeron {len(pares)} pares mensaje/hash del pcap (keyid={pares[0]['keyid']}).")

    # Usamos el primer par como objetivo principal de la búsqueda;
    # los demás sirven para verificación cruzada del candidato encontrado.
    objetivo = pares[0]
    mensaje_rip_hex = objetivo["mensaje_hex"]
    hash_real = objetivo["hash_real"]

    gestor = GestorChunks(LONGITUDES, len(ALFABETO), CHUNK_SIZE)
    print(f"[MASTER] Longitudes a probar: {LONGITUDES}")
    print(f"[MASTER] Total de combinaciones: {gestor.total_combinaciones():,}")
    print(f"[MASTER] Total de chunks estimado: {gestor.total_chunks_estimado():,} (tamaño {CHUNK_SIZE:,} c/u)")

    evento_hallado = threading.Event()
    resultados = {'clave': None}

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen()
    servidor.settimeout(1.0)
    print(f"[MASTER] Escuchando en {HOST}:{PORT}...")
    print(f"[MASTER] IP local para que workers remotos se conecten: {obtener_ip_local()}:{PORT}")
    print(f"[MASTER]   (en el worker: python3 worker.py {obtener_ip_local()})")

    hilos = []
    try:
        while not evento_hallado.is_set():
            if cola_chunks_vacia_y_sin_hilos_activos(gestor, hilos):
                break
            try:
                conn, addr = servidor.accept()
                hilo = threading.Thread(
                    target=manejar_worker,
                    args=(conn, addr, mensaje_rip_hex, hash_real, gestor, evento_hallado, resultados, pares)
                )
                hilo.start()
                hilos.append(hilo)
            except socket.timeout:
                continue
    finally:
        for hilo in hilos:
            hilo.join()
        servidor.close()

    clave_final = resultados['clave']
    if clave_final:
        print(f"[MASTER] Proceso finalizado. La clave secreta es: '{clave_final}'")
    else:
        print("[MASTER] Proceso finalizado. No se encontró la clave en los rangos probados.")


if __name__ == "__main__":
    iniciar_master()