"""
Worker cliente para el descifrado de clave HMAC-MD5.
Se conecta al Master, procesa los bloques de búsqueda asignados convirtiendo
adecuadamente las secuencias hex a bytes y retorna las respuestas mediante ACK.
"""

import hashlib
import hmac
import json
import socket
import argparse


ALFABETO = "0123456789abcdefghijklmnopqrstuvwxyz"
BASE = len(ALFABETO)


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    """Calcula el hash HMAC-MD5 para un mensaje y clave dados."""
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


def indice_a_clave(n: int) -> str:
    """
    Convierte un entero n (0..N-1) a su clave correspondiente de 1 a 6 caracteres.
    """
    for longitud in range(1, 7):
        combinaciones = BASE ** longitud
        if n < combinaciones:
            res = []
            for _ in range(longitud):
                res.append(ALFABETO[n % BASE])
                n //= BASE
            print(("0" * (8 - len(res))) + "".join(reversed(res)))
            return ("0" * (8 - len(res))) + "".join(reversed(res))
        n -= combinaciones
    raise ValueError("Índice fuera de rango")


def procesar_tarea(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int) -> str | None:
    """Busca por fuerza bruta la clave HMAC probando el rango numérico asignado."""
    for num in range(inicio, fin):
        hex_str = indice_a_clave(num).encode('utf-8').hex()
        clave_bytes = bytes.fromhex(hex_str)
        hash_calculado = calcular_hash_hmac(mensaje_rip_bytes, clave_bytes)

        if hash_real == hash_calculado:
            return hex_str

    return None


def iniciar_worker() -> None:
    """Mantiene la conexión activa con el Master procesando bloques de tareas recibidos."""
    parser = argparse.ArgumentParser(description="Worker node: processes tasks from the master")
    parser.add_argument("--host", required=True, help="Master's IP address")
    parser.add_argument("--port", type=int, default=5000, help="Master's port (default: 5000)")
    args = parser.parse_args()

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            print(f"[WORKER] Connecting to master at {args.host}:{args.port} ...")
            cliente.connect((args.host, args.port))
            print("[WORKER] Conectado al Master.")

            while True:
                data = cliente.recv(4096)
                if not data:
                    print("[WORKER] El Master cerró la conexión.")
                    break

                datos = json.loads(data.decode('utf-8'))
                id_tarea = datos["id_tarea"]
                mensaje_rip_bytes = bytes.fromhex(datos["mensaje"])
                hash_real = datos["hash"]
                inicio = datos["inicio"]
                fin = datos["fin"]

                print(f"[WORKER] Procesando Tarea #{id_tarea} (Rango: {inicio} a {fin})")

                res = procesar_tarea(mensaje_rip_bytes, hash_real, inicio, fin)

                respuesta = json.dumps({"id_tarea": id_tarea, "resultado": res})
                cliente.sendall(respuesta.encode('utf-8'))

                if res is not None:
                    print(f"[WORKER] ¡Clave encontrada en la Tarea #{id_tarea}!")
                    break

    except ConnectionRefusedError:
        print("[WORKER] Error: No se pudo conectar al Master. Asegúrate de que está escuchando.")
    except Exception as e:
        print(f"[WORKER] Ocurrió un error insospechado: {e}")
    finally:
        print("[WORKER] Conexión y ejecución finalizadas.")


if __name__ == "__main__":
    iniciar_worker()