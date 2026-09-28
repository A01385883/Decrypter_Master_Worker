"""
Master.py - Coordinador de búsqueda por fuerza bruta HMAC-MD5 para RIPv2.
Espera a que se conecten N workers remotos antes de iniciar la repartición
de tareas entre la red y el hilo local.
"""

import argparse
import hashlib
import hmac
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
# CONFIGURACIÓN GENERAL
# ==============================================================================
ARCHIVO_PCAP = "rip_passkey_size_06_02.pcap"
ALFABETO = string.ascii_lowercase + string.digits  # 'abcdefghijklmnopqrstuvwxyz0123456789'
BASE = len(ALFABETO)

# Variable por defecto para requerir N workers antes de empezar
WORKERS_REQUERIDOS = 2


# ==============================================================================
# 1. PARSER DINÁMICO DE CAPTURAS PCAP (ETHERNET / IP / UDP)
# ==============================================================================
def extraer_datos_rip_pcap(filepath: str) -> Tuple[bytes, str]:
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"El archivo '{filepath}' no se encuentra en el directorio actual.")

    with open(filepath, "rb") as f:
        data = f.read()

    if len(data) < 24:
        raise ValueError("El archivo es demasiado pequeño para ser un PCAP válido.")

    magic = data[:4]
    if magic in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4"):
        endian = "<" if magic == b"\xd4\xc3\xb2\xa1" else ">"
    else:
        return _extraer_por_firma(data)

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
                print(f"[MASTER-PCAP] Hash HMAC-MD5 extraído: {hash_real}")
                return mensaje_rip, hash_real

    return _extraer_por_firma(data)


def _extraer_por_firma(data: bytes) -> Tuple[bytes, str]:
    pos = 0
    while True:
        idx = data.find(b"\x02\x02", pos)
        if idx == -1:
            break

        if idx + 8 < len(data) and data[idx + 4 : idx + 8] == b"\xff\xff\x00\x02":
            for tam in (96, 112, 80):
                if idx + tam <= len(data):
                    candidato = data[idx : idx + tam]
                    mensaje_rip = candidato[:-16]
                    hash_real = candidato[-16:].hex()
                    if hash_real != "00000000000000000000000000000000":
                        print(f"[MASTER-PCAP] Trama RIPv2 identificada en offset {idx}.")
                        print(f"[MASTER-PCAP] Hash HMAC-MD5 extraído: {hash_real}")
                        return mensaje_rip, hash_real

        pos = idx + 1

    raise ValueError("No se pudo localizar una trama RIPv2 HMAC-MD5 válida en el archivo.")


# ==============================================================================
# 2. FUNCIONES DE RED, CONVERSIÓN Y LÓGICA DE BÚSQUEDA
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


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


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
        if calcular_hash_hmac(mensaje_rip_bytes, clave_bytes) == hash_real:
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
) -> None:
    print("[MASTER-LOCAL] Hilo de búsqueda local del Master listo.")
    while not evento_hallado.is_set():
        try:
            tarea = cola_tareas.get(timeout=1.0)
        except queue.Empty:
            if not tareas_en_progreso and cola_tareas.empty():
                break
            continue

        id_tarea = tarea["id_tarea"]
        with lock_tareas:
            tareas_en_progreso[id_tarea] = (tarea, time.time())

        res = procesar_tarea_local(
            mensaje_rip_bytes, hash_real, tarea["inicio"], tarea["fin"], key_length, evento_hallado
        )

        with lock_tareas:
            tareas_en_progreso.pop(id_tarea, None)

        if res is not None and not evento_hallado.is_set():
            resultados["clave"] = res
            print(f"\n[MASTER-LOCAL] ¡Clave encontrada localmente: {res}!")
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

                with lock_tareas:
                    tareas_en_progreso.pop(id_tarea, None)

                cola_tareas.task_done()

                if resultado is not None and not evento_hallado.is_set():
                    resultados["clave"] = resultado
                    print(f"\n[MASTER] ¡Clave encontrada por {addr}: {resultado}!")
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
# 3. PUNTO DE ENTRADA PRINCIPAL CON ESPERA DE WORKERS
# ==============================================================================
def main() -> None:
    parser = argparse.ArgumentParser(description="Master HMAC-MD5 Fuerza Bruta ASCII")
    parser.add_argument("--key-length", "-l", type=int, default=6, help="Longitud de clave ASCII")
    parser.add_argument("--num-workers", "-w", type=int, default=WORKERS_REQUERIDOS, help="Cantidad de workers remotos a esperar antes de iniciar")
    parser.add_argument("--num-bloques", type=int, default=1000, help="Número de bloques de trabajo")
    parser.add_argument("--host", default="0.0.0.0", help="Interfaz de escucha (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Puerto de escucha (default: 5000)")
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
    print(f"[INFO WORKER] Ejecuta esta orden en las computadoras worker:")
    print(f"             python worker.py --host {ip_lan} --port {args.port}")
    print("=" * 65 + "\n")

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((args.host, args.port))
    servidor.listen(args.num_workers)

    # --------------------------------------------------------------------------
    # BARRERA DE ESPERA: Aguardar hasta que exactamente N workers se conecten
    # --------------------------------------------------------------------------
    print(f"[MASTER] Esperando a que se conecten exactamente {args.num_workers} worker(s)...")
    conexiones_remotas: List[Tuple[socket.socket, Tuple[str, int]]] = []

    while len(conexiones_remotas) < args.num_workers:
        conn, addr = servidor.accept()
        conexiones_remotas.append((conn, addr))
        print(f"[MASTER] Worker conectado desde {addr} ({len(conexiones_remotas)}/{args.num_workers})")

    print(f"\n[MASTER] ¡Todos los {args.num_workers} worker(s) están conectados!")
    print("[MASTER] Iniciando la generación de tareas y distribución de carga...\n")

    # Inicializar la cola de tareas una vez que todos están listos
    cola_tareas = generar_cola_tareas(total_combinaciones, args.num_bloques)
    tareas_en_progreso: Dict[int, Tuple[dict, float]] = {}
    lock_tareas = threading.Lock()
    evento_hallado = threading.Event()
    resultados = {"clave": None}

    hilos: List[threading.Thread] = []

    # 1. Hilo supervisor de timeouts
    hilo_supervisor = threading.Thread(
        target=supervisor_tareas,
        args=(cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, args.timeout),
        daemon=True,
    )
    hilo_supervisor.start()

    # 2. Hilo local del Master para apoyar con cálculos
    hilo_master_local = threading.Thread(
        target=worker_local_master,
        args=(mensaje_rip, hash_real, args.key_length, cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, resultados),
    )
    hilo_master_local.start()
    hilos.append(hilo_master_local)

    # 3. Asignar hilos de trabajo a las conexiones recibidas previamente
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
            ),
        )
        hilo_remoto.start()
        hilos.append(hilo_remoto)

    # Permitir conexiones adicionales en caliente mientras la búsqueda continúe
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

    clave_final = resultados["clave"]
    if clave_final:
        print(f"\n[MASTER] ¡ÉXITO! La clave secreta hallada es: '{clave_final}'")
    else:
        print("\n[MASTER] Proceso finalizado. No se encontró la clave en los rangos probados.")


if __name__ == "__main__":
    main()