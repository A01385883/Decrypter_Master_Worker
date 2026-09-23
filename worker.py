"""
Worker cliente para el descifrado de clave HMAC-MD5.
Se conecta al Master, procesa los bloques de búsqueda asignados convirtiendo
adecuadamente las secuencias hex a bytes y retorna las respuestas mediante ACK.
"""

import hashlib
import hmac
import json
import socket


HOST = '127.0.0.1'
PORT = 65432


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    """Calcula el hash HMAC-MD5 para un mensaje y clave dados."""
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


def procesar_tarea(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int) -> str | None:
    """Busca por fuerza bruta la clave HMAC probando el rango numérico asignado."""
    for num in range(inicio, fin):
        hex_str = f"{num:06x}"
        clave_bytes = bytes.fromhex(hex_str)
        hash_calculado = calcular_hash_hmac(mensaje_rip_bytes, clave_bytes)

        if hash_real == hash_calculado:
            return hex_str

    return None


def iniciar_worker() -> None:
    """Mantiene la conexión activa con el Master procesando bloques de tareas recibidos."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            cliente.connect((HOST, PORT))
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