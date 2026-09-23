"""
Master coordinador de búsqueda por fuerza bruta HMAC-MD5.
Administra las tareas mediante una cola segura, procesa rangos de búsqueda
en un hilo local propio y garantiza la reasignación de tareas si un worker falla.
"""

import hashlib
import hmac
import json
import queue
import socket
import threading
import time


HOST = '127.0.0.1'
PORT = 65432
TIMEOUT_TAREA_SEGUNDOS = 10.0


def calcular_hash_hmac(mensaje_bytes: bytes, clave_bytes: bytes) -> str:
    """Calcula el hash HMAC-MD5 para un mensaje y clave dados."""
    return hmac.new(clave_bytes, mensaje_bytes, hashlib.md5).hexdigest()


def generar_cola_tareas(total_combinaciones: int, num_bloques: int) -> queue.Queue:
    """Divide el espacio total de búsqueda en una cola de tareas independientes."""
    cola: queue.Queue = queue.Queue()
    bloque = total_combinaciones // num_bloques
    for i in range(num_bloques):
        inicio = i * bloque
        fin = total_combinaciones if i == num_bloques - 1 else (i + 1) * bloque
        cola.put({"id_tarea": i + 1, "inicio": inicio, "fin": fin})
    return cola


def procesar_tarea_local(mensaje_rip_bytes: bytes, hash_real: str, inicio: int, fin: int, evento_hallado: threading.Event) -> str | None:
    """Busca la clave en el rango asignado dentro del proceso local del Master."""
    for num in range(inicio, fin):
        if evento_hallado.is_set():
            return None
        hex_str = f"{num:06x}"
        clave_bytes = bytes.fromhex(hex_str)
        if calcular_hash_hmac(mensaje_rip_bytes, clave_bytes) == hash_real:
            return hex_str
    return None


def worker_local_master(
    mensaje_rip_bytes: bytes,
    hash_real: str,
    cola_tareas: queue.Queue,
    tareas_en_progreso: dict,
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event,
    resultados: dict
) -> None:
    """Hilo secundario del Master para procesar tareas por su cuenta."""
    print("[MASTER-LOCAL] Hilo de búsqueda local iniciado.")
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

        res = procesar_tarea_local(mensaje_rip_bytes, hash_real, tarea["inicio"], tarea["fin"], evento_hallado)

        with lock_tareas:
            tareas_en_progreso.pop(id_tarea, None)

        if res is not None and not evento_hallado.is_set():
            resultados['clave'] = res
            print(f"\n[MASTER-LOCAL] ¡Clave encontrada localmente por el Master: {res}!")
            evento_hallado.set()
            cola_tareas.task_done()
            break

        cola_tareas.task_done()


def manejar_worker_remoto(
    conn: socket.socket,
    addr: tuple[str, int],
    mensaje_rip_hex: str,
    hash_real: str,
    cola_tareas: queue.Queue,
    tareas_en_progreso: dict,
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event,
    resultados: dict
) -> None:
    """Atiende a un Worker externo conectándolo y asignándole tareas de la cola."""
    print(f"[MASTER] Conectado con Worker en {addr}")
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
                "id_tarea": id_tarea,
                "mensaje": mensaje_rip_hex,
                "hash": hash_real,
                "inicio": tarea["inicio"],
                "fin": tarea["fin"]
            }

            try:
                conn.sendall(json.dumps(payload).encode('utf-8'))
                data = conn.recv(1024)

                if not data:
                    raise ConnectionError("Worker se desconectó inesperadamente.")

                respuesta = json.loads(data.decode('utf-8'))
                resultado = respuesta.get('resultado')

                with lock_tareas:
                    tareas_en_progreso.pop(id_tarea, None)

                cola_tareas.task_done()

                if resultado is not None and not evento_hallado.is_set():
                    resultados['clave'] = resultado
                    print(f"\n[MASTER] ¡Clave encontrada por {addr}: {resultado}!")
                    evento_hallado.set()
                    break

            except Exception as e:
                print(f"[MASTER] Error de red con Worker {addr} en tarea {id_tarea}: {e}")
                with lock_tareas:
                    if id_tarea in tareas_en_progreso:
                        tareas_en_progreso.pop(id_tarea, None)
                        cola_tareas.put(tarea)
                        print(f"[MASTER] Tarea {id_tarea} devuelta a la cola por fallo de red.")
                break

    finally:
        conn.close()


def supervisor_tareas(
    cola_tareas: queue.Queue,
    tareas_en_progreso: dict,
    lock_tareas: threading.Lock,
    evento_hallado: threading.Event
) -> None:
    """Hilo supervisor (Watchdog) que detecta tareas colgadas y las reasigna."""
    while not evento_hallado.is_set():
        time.sleep(2.0)
        ahora = time.time()
        with lock_tareas:
            tareas_expiradas = []
            for id_tarea, (tarea, timestamp) in list(tareas_en_progreso.items()):
                if ahora - timestamp > TIMEOUT_TAREA_SEGUNDOS:
                    tareas_expiradas.append(id_tarea)

            for id_tarea in tareas_expiradas:
                tarea, _ = tareas_en_progreso.pop(id_tarea)
                cola_tareas.put(tarea)
                print(f"[SUPERVISOR] Tarea {id_tarea} reasignada por timeout (> {TIMEOUT_TAREA_SEGUNDOS}s).")

        if cola_tareas.empty() and not tareas_en_progreso:
            break


def iniciar_master() -> None:
    """Inicializa datos, configura la red y coordina los trabajadores locales y remotos."""
    mensaje_rip = bytes.fromhex(
        "0202080048be7402020000ffff0003002c011400000000000000000000000200000a000100ffffff000000000000000001"
    )
    clave_temporal = bytes.fromhex("a1b2c3")
    hash_real = calcular_hash_hmac(mensaje_rip, clave_temporal)

    total_combinaciones = 16**6
    num_bloques = 12
    cola_tareas = generar_cola_tareas(total_combinaciones, num_bloques)

    tareas_en_progreso: dict[int, tuple[dict, float]] = {}
    lock_tareas = threading.Lock()
    evento_hallado = threading.Event()
    resultados = {'clave': None}

    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen()
    servidor.settimeout(1.0)
    print(f"[MASTER] Escuchando en {HOST}:{PORT}...")

    hilos = []

    hilo_supervisor = threading.Thread(
        target=supervisor_tareas,
        args=(cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado),
        daemon=True
    )
    hilo_supervisor.start()

    hilo_master_local = threading.Thread(
        target=worker_local_master,
        args=(mensaje_rip, hash_real, cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, resultados)
    )
    hilo_master_local.start()
    hilos.append(hilo_master_local)

    try:
        while not evento_hallado.is_set():
            with lock_tareas:
                if cola_tareas.empty() and not tareas_en_progreso:
                    break
            try:
                conn, addr = servidor.accept()
                hilo_remoto = threading.Thread(
                    target=manejar_worker_remoto,
                    args=(conn, addr, mensaje_rip.hex(), hash_real, cola_tareas, tareas_en_progreso, lock_tareas, evento_hallado, resultados)
                )
                hilo_remoto.start()
                hilos.append(hilo_remoto)
            except socket.timeout:
                continue
    finally:
        servidor.close()
        for hilo in hilos:
            hilo.join()

    clave_final = resultados['clave']
    if clave_final:
        print(f"\n[MASTER] Proceso finalizado. La clave secreta (hex) es: '{clave_final}'")
    else:
        print("\n[MASTER] Proceso finalizado. No se encontró la clave en ningún rango.")


if __name__ == "__main__":
    iniciar_master()