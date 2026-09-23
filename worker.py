"""
sim_worker.py

Connects to sim_master.py over TCP, pulls tasks one at a time, does some
(simulated) work, and sends the result back.

Usage (on each worker computer):
    python sim_worker.py --host <MASTER_LAN_IP> --port 5000
"""

import socket
import json
import argparse
import time
import random

def recv_message(sock):
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode())

def send_message(sock, obj):
    sock.sendall((json.dumps(obj) + "\n").encode())

def simulate_task(payload):
    """Placeholder for real work. Swap this out for your actual computation."""
    time.sleep(random.uniform(0.5, 2.0))
    return payload ** 2

def main():
    parser = argparse.ArgumentParser(description="Worker node: processes tasks from the master")
    parser.add_argument("--host", required=True, help="Master's IP address")
    parser.add_argument("--port", type=int, default=5000, help="Master's port (default: 5000)")
    args = parser.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    print(f"[WORKER] Connecting to master at {args.host}:{args.port} ...")
    sock.connect((args.host, args.port))
    print("[WORKER] Connected. Waiting for tasks...")

    try:
        while True:
            message = recv_message(sock)
            if message is None:
                print("[WORKER] Master closed the connection.")
                break

            if message.get("cmd") == "done":
                print("[WORKER] No more tasks. Shutting down.")
                break

            task_id = message["task_id"]
            payload = message["payload"]
            print(f"[WORKER] Received task {task_id} (payload={payload})")

            result_value = simulate_task(payload)
            send_message(sock, {"task_id": task_id, "result": result_value})
            print(f"[WORKER] Sent result for task {task_id}: {result_value}")
    finally:
        sock.close()


if __name__ == "__main__":
    main()