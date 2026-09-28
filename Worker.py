"""
Worker cliente para fuerza bruta HMAC-MD5.
Genera combinaciones ASCII compuestas por minúsculas (a-z) y números (0-9)
dentro del rango numérico asignado por el Master.
"""

import argparse
import hashlib
import hmac
import json
import socket
import string
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
    """Mapea un valor entero a una cadena de caracteres usando el alfabeto (a-z, 0-9)."""
    res = []
    for _ in range(length):
        res.append(ALFABETO[num % BASE])
        num //= BASE
    return "".join(reversed(res))


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


def procesar_tarea(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int, key_length: int) -> str | None:
    """Prueba el rango numérico asignado traduciendo cada valor a su representación ASCII."""
    for num in range(inicio, fin):
        clave_str = int_a_string_ascii(num, key_length)
        clave_bytes = clave_str.encode("utf-8")
        if calcular_hash_hmac(mensaje_rip_bytes, clave_bytes) == hash_real:
            return clave_str
    return None


def main() -> None:
    parser = argparse.ArgumentParser(description="Worker HMAC-MD5 ASCII")
    parser.add_argument("--host", required=True, help="IP del Master")
    parser.add_argument("--port", type=int, default=5000, help="Puerto (default: 5000)")
    args = parser.parse_args()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            print(f"[WORKER] Conectando al Master en {args.host}:{args.port}...")
            cliente.connect((args.host, args.port))
            print("[WORKER] Conectado exitosamente.")

            while True:
                datos = recv_message(cliente)
                if datos is None or datos.get("cmd") == "done":
                    print("[WORKER] Finalizado o no hay más tareas.")
                    break

                id_tarea = datos["id_tarea"]
                mensaje_rip_bytes = bytes.fromhex(datos["mensaje"])
                hash_real = datos["hash"]
                inicio = datos["inicio"]
                fin = datos["fin"]
                key_length = datos.get("key_length", 6)

                print(f"[WORKER] Procesando Tarea #{id_tarea} (Rango: {inicio} a {fin}, Largo ASCII: {key_length})")

                res = procesar_tarea(mensaje_rip_bytes, hash_real, inicio, fin, key_length)

                send_message(cliente, {"id_tarea": id_tarea, "resultado": res})

                if res is not None:
                    print(f"[WORKER] ¡Clave encontrada en Tarea #{id_tarea}: {res}!")
                    break

    except ConnectionRefusedError:
        print("[WORKER] Error: No se pudo conectar al Master.")
    except Exception as e:
        print(f"[WORKER] Ocurrió un error: {e}")


if __name__ == "__main__":
    main()