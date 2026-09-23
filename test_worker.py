import socket
import sys

PORT = 65432


def iniciar_worker_prueba() -> None:
    master_host = sys.argv[1] if len(sys.argv) > 1 else '10.117.151.200'
    print(f"[WORKER-TEST] Intentando conectar a {master_host}:{PORT}...")

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as cliente:
            cliente.settimeout(10.0)  # no te deja esperando para siempre si algo falla
            cliente.connect((master_host, PORT))
            print("[WORKER-TEST] ¡Conectado!")

            data = cliente.recv(1024)
            print(f"[WORKER-TEST] Master dijo: {data.decode('utf-8').strip()}")

            cliente.sendall(b"hola desde el worker\n")
            print("[WORKER-TEST] Respuesta enviada. Prueba exitosa.")

    except socket.timeout:
        print("[WORKER-TEST] Error: tiempo de espera agotado (timeout). Problema de red/firewall.")
    except ConnectionRefusedError:
        print("[WORKER-TEST] Error: conexión rechazada. ¿El master está corriendo en esa IP/puerto?")
    except OSError as e:
        print(f"[WORKER-TEST] Error de red: {e}")


if __name__ == "__main__":
    iniciar_worker_prueba()
