import hashlib
import hmac
import json
import socket
import sys
import time

PORT = 65432

HEARTBEAT_INTERVALO_SEG = 2.0   # mandar heartbeat cada N segundos (no por conteo de intentos)
CHEQUEO_CADA = 20_000           # cada cuántas iteraciones se revisa el reloj (evita llamar time.time() en cada vuelta)
ALFABETO = "abcdefghijklmnopqrstuvwxyz0123456789"  # minúsculas + dígitos


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


def numero_a_clave(num: int, longitud: int) -> str:
    """Convierte un número a una cadena de `longitud` caracteres en base 36 (a-z0-9)."""
    base = len(ALFABETO)
    caracteres = []
    for _ in range(longitud):
        num, resto = divmod(num, base)
        caracteres.append(ALFABETO[resto])
    return ''.join(reversed(caracteres))


def enviar_json(conn: socket.socket, obj: dict) -> None:
    conn.sendall((json.dumps(obj) + "\n").encode('utf-8'))


def leer_linea(conn: socket.socket, buffer: bytearray) -> dict | None:
    """Lee del socket hasta completar una línea JSON."""
    while b"\n" not in buffer:
        data = conn.recv(4096)
        if not data:
            return None
        buffer.extend(data)
    linea, _, resto = buffer.partition(b"\n")
    buffer.clear()
    buffer.extend(resto)
    return json.loads(linea.decode('utf-8')) if linea.strip() else None


def procesar_chunk(conn: socket.socket, mensaje_rip_bytes: bytes, hash_real: str, longitud: int, inicio: int, fin: int) -> str | None:
    """Prueba el rango asignado (claves de `longitud` caracteres), mandando heartbeats por tiempo transcurrido."""
    ultimo_heartbeat = time.time()

    for i, num in enumerate(range(inicio, fin)):
        clave_str = numero_a_clave(num, longitud)
        clave_bytes = clave_str.encode('utf-8')
        hash_calculado = calcular_hash_hmac(mensaje_rip_bytes, clave_bytes)

        if hash_real == hash_calculado:
            return clave_str

        if i % CHEQUEO_CADA == 0 and i > 0:
            ahora = time.time()
            if ahora - ultimo_heartbeat >= HEARTBEAT_INTERVALO_SEG:
                enviar_json(conn, {"tipo": "heartbeat", "longitud": longitud, "avance": inicio + i})
                ultimo_heartbeat = ahora

    return None


def iniciar_worker() -> None:
    master_host = sys.argv[1] if len(sys.argv) > 1 else '10.22.148.39'
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            cliente.connect((master_host, PORT))
            print(f"[WORKER] Conectado al Master en {master_host}:{PORT}.")
            buffer = bytearray()

            while True:
                msg = leer_linea(cliente, buffer)
                if msg is None:
                    print("[WORKER] Master cerró la conexión.")
                    break

                tipo = msg.get("tipo")

                if tipo == "sin_trabajo":
                    print("[WORKER] No quedan chunks por procesar. Terminando.")
                    break

                if tipo == "tarea":
                    mensaje_rip_bytes = bytes.fromhex(msg["mensaje"])
                    hash_real = msg["hash"]
                    longitud = msg["longitud"]
                    inicio, fin = msg["inicio"], msg["fin"]
                    print(f"[WORKER] Procesando chunk longitud={longitud} [{inicio}:{fin}] ({fin - inicio} claves)")

                    res = procesar_chunk(cliente, mensaje_rip_bytes, hash_real, longitud, inicio, fin)

                    enviar_json(cliente, {"tipo": "chunk_terminado", "resultado": res})

                    if res:
                        print(f"[WORKER] ¡Clave encontrada!: {res}")
                        break
                    # si no encontró nada, vuelve al loop a esperar el siguiente "tarea"

    except ConnectionRefusedError:
        print("[WORKER] Error: No se pudo conectar al Master. Asegúrate de que está escuchando.")
    except Exception as e:
        print(f"[WORKER] Ocurrió un error inesperado: {e}")
    finally:
        print("[WORKER] Tarea finalizada y conexión cerrada.")


if __name__ == "__main__":
    iniciar_worker()