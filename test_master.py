"""
Prueba mínima de conectividad -- SOLO valida que un worker se pueda
conectar al master por la red. No tiene nada de lógica de brute force.
Úsalo para descartar problemas de red antes de correr el sistema completo.
"""

import socket

HOST = '0.0.0.0'  # escucha en todas las interfaces
PORT = 65432


def iniciar_master_prueba() -> None:
    servidor = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    servidor.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    servidor.bind((HOST, PORT))
    servidor.listen()
    print(f"[MASTER-TEST] Escuchando en {HOST}:{PORT}...")
    print("[MASTER-TEST] Esperando conexión de un worker (Ctrl+C para cancelar)...")

    conn, addr = servidor.accept()
    print(f"[MASTER-TEST] ¡Conexión aceptada desde {addr}!")

    with conn:
        conn.sendall(b"hola desde el master\n")
        data = conn.recv(1024)
        print(f"[MASTER-TEST] Worker respondió: {data.decode('utf-8').strip()}")

    print("[MASTER-TEST] Prueba exitosa. La conexión funciona correctamente.")
    servidor.close()


if __name__ == "__main__":
    iniciar_master_prueba()
