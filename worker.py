"""
Worker.py - Cliente de procesamiento para fuerza bruta RIPv2 RFC 2082.
Mide el tiempo de resolución por tarea y calcula el rendimiento individual
en Hashes por segundo (H/s) enviado en la respuesta ACK al Master.

Uso:
    python worker.py --host <IP_MASTER> --port 5000
"""

import argparse
import hashlib
import json
import socket
import string
import time
from typing import Any

ALFABETO = string.ascii_lowercase + string.digits
BASE = len(ALFABETO)


# --- Networking y serialización ---
def send_message(sock: socket.socket, obj: Any) -> None:
    """Envía un objeto JSON serializado con terminador de línea."""
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv_message(sock: socket.socket) -> Any | None:
    """Lee un mensaje JSON delimitado por nuevas líneas desde el socket."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))


# --- Conversión de enteros a clave ASCII ---
def int_a_string_ascii(num: int, length: int) -> str:
    """Convierte un número entero en una cadena de longitud fija usando el alfabeto."""
    res = []
    for _ in range(length):
        res.append(ALFABETO[num % BASE])
        num //= BASE
    return "".join(reversed(res))


# --- Cálculo de hashes RFC 2082 ---
def calcular_hash_rfc2082(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    """Calcula el hash MD5 del formato mensaje + clave_padded usado por el master."""
    clave_padded = clave_bytes.ljust(16, b"\x00")
    buffer_completo = mensaje_bytes + clave_padded
    return hashlib.md5(buffer_completo).hexdigest()


# --- Búsqueda en un rango ---
def procesar_tarea(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int, key_length: int) -> str | None:
    """Prueba todas las claves del rango solicitado y devuelve la que coincide."""
    for num in range(inicio, fin):
        clave_str = int_a_string_ascii(num, key_length)
        clave_bytes = clave_str.encode("utf-8")
        if calcular_hash_rfc2082(mensaje_rip_bytes, clave_bytes) == hash_real:
            return clave_str
    return None


# --- Arranque y ciclo del worker ---
def parse_args() -> argparse.Namespace:
    """Obtiene los parámetros del cliente worker desde la línea de comandos."""
    parser = argparse.ArgumentParser(description="Worker RFC 2082 con Métricas H/s")
    parser.add_argument("--host", required=True, help="IP del Master")
    parser.add_argument("--port", type=int, default=5000, help="Puerto (default: 5000)")
    return parser.parse_args()


def conectar_con_master(host: str, port: int) -> socket.socket:
    """Establece la conexión TCP con el master."""
    cliente = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[WORKER] Conectando al Master en {host}:{port}...")
    cliente.connect((host, port))
    print("[WORKER] Conectado exitosamente. En espera de tareas...")
    return cliente


def ejecutar_tarea(cliente: socket.socket, datos: dict[str, Any]) -> bool:
    """Procesa una tarea recibida del master y responde con el resultado o una señal de fin."""
    if datos is None or datos.get("cmd") == "done":
        print("[WORKER] El Master finalizó la sesión o no hay más tareas.")
        return False

    id_tarea = datos["id_tarea"]
    mensaje_rip_bytes = bytes.fromhex(datos["mensaje"])
    hash_real = datos["hash"]
    inicio = datos["inicio"]
    fin = datos["fin"]
    key_length = datos.get("key_length", 6)

    total_evaluaciones = fin - inicio
    print(f"[WORKER] Procesando Tarea #{id_tarea} (Rango: {inicio} a {fin} | {total_evaluaciones:,} iteraciones)")

    t_inicio = time.time()
    resultado = procesar_tarea(mensaje_rip_bytes, hash_real, inicio, fin, key_length)
    t_transcurrido = time.time() - t_inicio

    rate_individual = total_evaluaciones / t_transcurrido if t_transcurrido > 0 else 0.0
    print(
        f"[WORKER] Tarea #{id_tarea} finalizada en {t_transcurrido:.2f}s "
        f"| Rendimiento Individual: {rate_individual:,.0f} H/s"
    )

    send_message(
        cliente,
        {
            "id_tarea": id_tarea,
            "resultado": resultado,
            "tiempo_segundos": t_transcurrido,
            "hashes_por_segundo": rate_individual,
        },
    )

    if resultado is not None:
        print(f"\n[WORKER] ¡CLAVE HALLADA en Tarea #{id_tarea}: '{resultado}'!")
        return False

    return True


def run_worker(host: str, port: int) -> None:
    """Mantiene al worker escuchando tareas del master hasta que termine la sesión."""
    try:
        with conectar_con_master(host, port) as cliente:
            while True:
                datos = recv_message(cliente)
                if not ejecutar_tarea(cliente, datos):
                    break
    except ConnectionRefusedError:
        print("[WORKER] Error: No se pudo conectar al Master. Revisa la IP y puerto.")
    except Exception as e:
        print(f"[WORKER] Error en ejecución: {e}")


def main() -> None:
    args = parse_args()
    run_worker(args.host, args.port)


if __name__ == "__main__":
    main()