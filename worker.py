"""
Worker.py - Cliente de procesamiento para fuerza bruta RIPv2 RFC 2082.
Mide el tiempo de resolución por tarea y calcula el rendimiento individual
en Hashes por segundo (H/s) enviado en la respuesta ACK al Master.

Uso:
    python Worker.py --host <IP_MASTER> --port 5000
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


def send_message(sock: socket.socket, obj: Any) -> None:
    sock.sendall((json.dumps(obj) + "\n").encode("utf-8"))


def recv_message(sock: socket.socket) -> Any | None:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode("utf-8"))


def int_a_string_ascii(num: int, length: int) -> str:
    res = []
    for _ in range(length):
        res.append(ALFABETO[num % BASE])
        num //= BASE
    return "".join(reversed(res))


def calcular_hash_rfc2082(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    clave_padded = clave_bytes.ljust(16, b"\x00")
    buffer_completo = mensaje_bytes + clave_padded  # mensaje + clave, NO clave+mensaje+clave
    return hashlib.md5(buffer_completo).hexdigest()


def procesar_tarea(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int, key_length: int) -> str | None:
    for num in range(inicio, fin):
        clave_str = int_a_string_ascii(num, key_length)
        clave_bytes = clave_str.encode("utf-8")
        if calcular_hash_rfc2082(mensaje_rip_bytes, clave_bytes) == hash_real:
            return clave_str
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Worker RFC 2082 con Métricas H/s")
    parser.add_argument("--host", required=True, help="IP del Master")
    parser.add_argument("--port", type=int, default=5000, help="Puerto (default: 5000)")
    args = parser.parse_args()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            print(f"[WORKER] Conectando al Master en {args.host}:{args.port}...")
            cliente.connect((args.host, args.port))
            print("[WORKER] Conectado exitosamente. En espera de tareas...")

            while True:
                datos = recv_message(cliente)
                if datos is None or datos.get("cmd") == "done":
                    print("[WORKER] El Master finalizó la sesión o no hay más tareas.")
                    break

                id_tarea = datos["id_tarea"]
                mensaje_rip_bytes = bytes.fromhex(datos["mensaje"])
                hash_real = datos["hash"]
                inicio = datos["inicio"]
                fin = datos["fin"]
                key_length = datos.get("key_length", 6)

                total_evaluaciones = fin - inicio
                print(f"[WORKER] Procesando Tarea #{id_tarea} (Rango: {inicio} a {fin} | {total_evaluaciones:,} iteraciones)")

                # Medición de tiempo por tarea
                t_inicio = time.time()
                res = procesar_tarea(mensaje_rip_bytes, hash_real, inicio, fin, key_length)
                t_transcurrido = time.time() - t_inicio

                # Cálculo de Hashes por Segundo (H/s) Individuales
                rate_individual = total_evaluaciones / t_transcurrido if t_transcurrido > 0 else 0.0

                print(
                    f"[WORKER] Tarea #{id_tarea} finalizada en {t_transcurrido:.2f}s "
                    f"| Rendimiento Individual: {rate_individual:,.0f} H/s"
                )

                # Enviar respuesta con métricas al Master
                send_message(
                    cliente,
                    {
                        "id_tarea": id_tarea,
                        "resultado": res,
                        "tiempo_segundos": t_transcurrido,
                        "hashes_por_segundo": rate_individual,
                    },
                )

                if res is not None:
                    print(f"\n[WORKER] ¡CLAVE HALLADA en Tarea #{id_tarea}: '{res}'!")
                    break

    except ConnectionRefusedError:
        print("[WORKER] Error: No se pudo conectar al Master. Revisa la IP y puerto.")
    except Exception as e:
        print(f"[WORKER] Error en ejecución: {e}")


if __name__ == "__main__":
    main()