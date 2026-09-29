"""
Master.py - Coordinador de búsqueda por fuerza bruta RIPv2 RFC 2082.
Genera la cola de tareas, supervisa timeouts, espera a N workers y calcula
el rendimiento global en Hashes por Segundo (H/s) de la red.

Uso:
    python Master.py -w 1 --key-length 6
"""

import argparse
import hashlib
import json
import os
import queue
import socket
import string
import struct
import threading
import time
from typing import Any, Dict, List, Tuple

# ==============================================================================
# CONFIGURACIÓN GENERAL Y ALFABETO ASCII
# ==============================================================================
ARCHIVO_PCAP = "rip2_capture.pcap"
ALFABETO = string.ascii_lowercase + string.digits  # 36 caracteres ('a-z', '0-9')
BASE = len(ALFABETO)
WORKERS_REQUERIDOS = 1


# ==============================================================================
# 1. PARSER DINÁMICO DE CAPTURAS PCAP (ETHERNET / IP / UDP)
# ==============================================================================
def extraer_datos_rip_pcap(filepath: str) -> Tuple[bytes, str]:
    """Lee un PCAP extrayendo el mensaje RIPv2 y los 16 bytes finales del digest."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"El archivo '{filepath}' no existe.")

    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("El archivo es demasiado pequeño para ser un PCAP válido.")

    magic = data[:4]
    endian = "<" if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4") else ">"
    offset = 24
    total_len = len(data)

    while offset + 16 <= total_len:
        pkt_header = data[offset : offset + 16]
        incl_len = struct.unpack(f"{endian}I", pkt_header[8:12])[0]
        offset += 16

        pkt_data = data[offset : offset + incl_len]
        offset += incl_len

        if len(pkt_data) < 42 or pkt_data[12:14] != b"\x08\x00":
            continue

        ip_header = pkt_data[14:34]
        if ip_header[9] != 17:  # UDP
            continue

        ip_hdr_len = (ip_header[0] & 0x0F) * 4
        udp_offset = 14 + ip_hdr_len

        if len(pkt_data) < udp_offset + 8:
            continue

        udp_header = pkt_data[udp_offset : udp_offset + 8]
        dest_port = struct.unpack(">H", udp_header[2:4])[0]

        if dest_port == 520:
            rip_payload = pkt_data[udp_offset + 8 :]
            if len(rip_payload) >= 36 and rip_payload[0] == 2 and rip_payload[1] == 2:
                mensaje_rip = rip_payload[:-16]
                hash_real = rip_payload[-16:].hex()
                print(f"[MASTER-PCAP] Paquete RIPv2 UDP localizado correctamente.")
                print(f"[MASTER-PCAP] Hash MD5 extraído: {hash_real}")
                return mensaje_rip, hash_real

    raise ValueError("No se pudo localizar una trama RIPv2 MD5 válida en el archivo.")


# ==============================================================================
# 2. FUNCIONES MATEMÁTICAS, RED Y ALGORITMO RFC 2082
# ==============================================================================
def obtener_ip_local() -> str:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = "127.0.0.1"
    finally:
        s.close()
    return ip


def int_a_string_ascii(num: int, length: int) -> str:
    res = []
    for _ in range(length):
        res.append(ALFABETO[num % BASE])
        num //= BASE
    return "".join(reversed(res))


def send_message(conn: socket.socket, obj: Any) -> None:
    conn.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv_message(conn: socket.socket) -> Any | None:
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))


def calcular_hash_rfc2082(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    clave_padded = clave_bytes.ljust(16, b"\x00")
    buffer_completo = mensaje_bytes + clave_padded  # mensaje + clave, NO clave+mensaje+clave
    return hashlib.md5(buffer_completo).hexdigest()


def generar_cola_tareas(total_combinaciones: int, num_bloques: int) -> queue.Queue:
    cola: queue.Queue = queue.Queue()
    bloque = total_combinaciones // num_bloques
    for i in range(num_bloques):
        inicio = i * bloque
        fin = total_combinaciones if i == num_bloques - 1 else (i + 1) * bloque
        cola.put({"id_tarea": i + 1, "inicio": inicio, "fin": fin})
    return cola


def procesar_tarea_local(
    mensaje_rip_bytes: bytes,
    hash_real: str,
    inicio: int,
    fin: int,
    key_length: int,
    evento_hallado: threading.Event,
) -> str | None:
    for num in range(inicio, fin):
        if evento_hallado.is_set():
            return None
        clave_str = int_a_string_ascii(num, key_length)
        clave_bytes = clave_str.encode("utf-8")
        if calcular_hash_rfc2082(mensaje_rip_bytes, clave_bytes) == hash_real:
            return clave_str
    return None


def worker_local_master(
    mensaje_rip_bytes: bytes,
    hash_real: str,
    key_length: int,
    cola_tareas: queue.Queue,
    tareas_en_progreso: Dict[int, Tuple[dict, float]],
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event,
    resultados: dict,
    estadisticas: dict,
) -> None:
    print("[MASTER-LOCAL] Hilo de búsqueda local del Master activo.")
    while not evento_hallado.is_set():
        try:
            tarea = cola_tareas.get(timeout=1.0)
        except queue.Empty:
            if not tareas_en_progreso and cola_tareas.empty():
                break
            continue

        id_tarea = tarea["id_tarea"]
        t_inicio = time.time()
        with lock_tareas:
            tareas_en_progreso[id_tarea] = (tarea, t_inicio)

        res = procesar_tarea_local(
            mensaje_rip_bytes, hash_real, tarea["inicio"], tarea["fin"], key_length, evento_hallado
        )
        t_transcurrido = time.time() - t_inicio

        with lock_tareas:
            tareas_en_progreso.pop(id_tarea, None)
            
            # Actualizar métricas globales
            evaluaciones = tarea["fin"] - tarea["inicio"]
            estadisticas["total_hashes"] += evaluaciones
            estadisticas["tiempo_acumulado"] += t_transcurrido
            rate_local = evaluaciones / t_transcurrido if t_transcurrido > 0 else 0
            print(f"[MASTER-LOCAL] Tarea #{id_tarea} completada en {t_transcurrido:.2f}s | Rendimiento: {rate_local:,.0f} H/s")

        if res is not None and not evento_hallado.is_set():
            resultados["clave"] = res
            print(f"\n[MASTER-LOCAL] ¡Clave encontrada localmente: '{res}'!")
            evento_hallado.set()
            cola_tareas.task_done()
            break

        cola_tareas.task_done()


def manejar_worker_remoto(
    conn: socket.socket,
    addr: Tuple[str, int],
    mensaje_rip_hex: str,
    hash_real: str,
    key_length: int,
    cola_tareas: queue.Queue,
    tareas_en_progreso: Dict[int, Tuple[dict, float]],
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event,
    resultados: dict,
    estadisticas: dict,
) -> None:
    try:
        while not evento_hallado.is_set():
            try:
                tarea = cola_tareas.get(timeout=1.0)
            except queue.Empty:
                break

            id_tarea = tarea["id_tarea"]
            with lock_tareas:
                tareas_en_progreso[id_tarea] = (tarea, time.time())

            payload = {
                "cmd": "task",
                "id_tarea": id_tarea,
                "mensaje": mensaje_rip_hex,
                "hash": hash_real,
                "inicio": tarea["inicio"],
                "fin": tarea["fin"],
                "key_length": key_length,
            }

            try:
                send_message(conn, payload)
                respuesta = recv_message(conn)

                if respuesta is None:
                    raise ConnectionError("Worker desconectado.")

                resultado = respuesta.get("resultado")
                t_tarea = respuesta.get("tiempo_segundos", 0.0)
                rate_worker = respuesta.get("hashes_por_segundo", 0.0)

                evaluaciones = tarea["fin"] - tarea["inicio"]

                with lock_tareas:
                    tareas_en_progreso.pop(id_tarea, None)
                    estadisticas["total_hashes"] += evaluaciones
                    estadisticas["tiempo_acumulado"] += t_tarea

                print(
                    f"[MASTER] Tarea #{id_tarea} recibida de {addr} en {t_tarea:.2f}s "
                    f"| Velocidad Worker: {rate_worker:,.0f} H/s"
                )

                cola_tareas.task_done()

                if resultado is not None and not evento_hallado.is_set():
                    resultados["clave"] = resultado
                    print(f"\n[MASTER] ¡Clave encontrada por Worker en {addr}: '{resultado}'!")
                    evento_hallado.set()
                    break

            except Exception as e:
                print(f"[MASTER] Error con Worker {addr} en tarea #{id_tarea}: {e}")
                with lock_tareas:
                    if id_tarea in tareas_en_progreso:
                        tareas_en_progreso.pop(id_tarea, None)
                        cola_tareas.put(tarea)
                break

        try:
            send_message(conn, {"cmd": "done"})
        except Exception:
            pass

    finally:
        conn.close()


def supervisor_tareas(
    cola_tareas: queue.Queue,
    tareas_en_progreso: Dict[int, Tuple[dict, float]],
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event,
    timeout_segundos: float,
) -> None:
    while not evento_hallado.is_set():
        time.sleep(2.0)
        ahora = time.time()
        with lock_tareas:
            tareas_expiradas = []
            for id_tarea, (tarea, timestamp) in list(tareas_en_progreso.items()):
                if ahora - timestamp > timeout_segundos:
                    tareas_expiradas.append(id_tarea)

            for id_tarea in tareas_expiradas:
                tarea, _ = tareas_en_progreso.pop(id_tarea)
                cola_tareas.put(tarea)
                print(f"[SUPERVISOR] Tarea #{id_tarea} reencolada por timeout (> {timeout_segundos}s).")

        if cola_tareas.empty() and not tareas_en_progreso:
            break


# ==============================================================================
# 3. MAIN
# ==============================================================================
def main() -> None:
    parser = argparse.ArgumentParser(description="Master HMAC RFC 2082 con Métricas de Rendimiento")
    parser.add_argument("--key-length", "-l", type=int, default=6, help="Longitud de clave ASCII")
    parser.add_argument("--num-workers", "-w", type=int, default=WORKERS_REQUERIDOS, help="Workers a esperar")
    parser.add_argument("--num-bloques", type=int, default=1000, help="Número de bloques")
    parser.add_argument("--host", default="0.0.0.0", help="Interfaz de escucha")
    parser.add_argument("--port", type=int, default=5000, help="Puerto de escucha")
    parser.add_argument("--timeout", type=float, default=60.0, help="Timeout por tarea (s)")
    args = parser.parse_args()

    print(f"[MASTER] Leyendo archivo PCAP: '{ARCHIVO_PCAP}'...")
    mensaje_rip, hash_real = extraer_datos_rip_pcap(ARCHIVO_PCAP)

    total_combinaciones = BASE ** args.key_length
    print(f"[MASTER] Alfabeto: letras minúsculas (a-z) + números (0-9) [{BASE} caracteres]")
    print(f"[MASTER] Longitud de clave: {args.key_length} caracteres")
    print(f"[MASTER] Espacio total de búsqueda: {total_combinaciones:,} combinaciones")

    ip_lan = obtener_ip_local()
    print("\n" + "=" * 65)
    print(f"[INFO WORKER] Comando para conectar los workers:")
    print(f"             python worker.py --host {ip_lan} --port {args.port}")
    print("=" * 65 + "\n")

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.port))
    servidor.listen(args.num_workers)

    print(f"[MASTER] Esperando a que se conecten exactamente {args.num_workers} worker(s)...")
    conexiones_remotas: List[Tuple[socket.socket, Tuple[str, int]]] = []

    while len(conexiones_remotas) < args.num_workers:
        conn, addr = servidor.accept()
        conexiones_remotas.append((conn, addr))
        print(f"[MASTER] Worker conectado desde {addr} ({len(conexiones_remotas)}/{args.num_workers})")

    print(f"\n[MASTER] ¡Todos los workers están conectados! Iniciando búsqueda...")

    cola_tareas = generar_cola_tareas(total_combinaciones, args.num_bloques)
    tareas_en_progreso: Dict[int, Tuple[dict, float]] = {}
    lock_tareas = threading.Lock()
    evento_hallado = threading.Event()
    resultados = {"clave": None}
    
    # Métricas globales de procesamiento
    estadisticas = {"total_hashes": 0, "tiempo_acumulado": 0.0}

    hilos: List[threading.Thread] = []

    hilo_supervisor = threading.Thread(
        target=supervisor_tareas,
        args=(cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, args.timeout),
        daemon=True,
    )
    hilo_supervisor.start()

    t_inicio_global = time.time()

    hilo_master_local = threading.Thread(
        target=worker_local_master,
        args=(mensaje_rip, hash_real, args.key_length, cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, resultados, estadisticas),
    )
    hilo_master_local.start()
    hilos.append(hilo_master_local)

    for conn, addr in conexiones_remotas:
        hilo_remoto = threading.Thread(
            target=manejar_worker_remoto,
            args=(
                conn,
                addr,
                mensaje_rip.hex(),
                hash_real,
                args.key_length,
                cola_tareas,
                tareas_en_progreso,
                lock_tareas,
                evento_hallado,
                resultados,
                estadisticas,
            ),
        )
        hilo_remoto.start()
        hilos.append(hilo_remoto)

    servidor.settimeout(1.0)
    try:
        while not evento_hallado.is_set():
            with lock_tareas:
                if cola_tareas.empty() and not tareas_en_progreso:
                    break
            try:
                conn, addr = servidor.accept()
                hilo_remoto = threading.Thread(
                    target=manejar_worker_remoto,
                    args=(
                        conn,
                        addr,
                        mensaje_rip.hex(),
                        hash_real,
                        args.key_length,
                        cola_tareas,
                        tareas_en_progreso,
                        lock_tareas,
                        evento_hallado,
                        resultados,
                        estadisticas,
                    ),
                )
                hilo_remoto.start()
                hilos.append(hilo_remoto)
            except socket.timeout:
                continue
    finally:
        servidor.close()
        for hilo in hilos:
            hilo.join()

    tiempo_total = time.time() - t_inicio_global
    clave_final = resultados["clave"]

    print("\n" + "=" * 65)
    print("RESUMEN Y MÉTRICAS DE EJECUCIÓN")
    print("=" * 65)
    if clave_final:
        print(f"¡ÉXITO! Clave secreta encontrada: '{clave_final}'")
    else:
        print("FINALIZADO: No se encontró la clave en los rangos probados.")

    hashes_evaluados = estadisticas["total_hashes"]
    rate_colectivo = hashes_evaluados / tiempo_total if tiempo_total > 0 else 0

    print(f"Tiempo total transcurrido:    {tiempo_total:.2f} segundos")
    print(f"Hashes evaluados totales:     {hashes_evaluados:,}")
    print(f"Rendimiento Colectivo Red:    {rate_colectivo:,.0f} H/s (Hashes/segundo)")
    print("=" * 65)


if __name__ == "__main__":
    main()