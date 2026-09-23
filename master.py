"""
sim_master.py

Distributes simulated tasks to worker processes running on other machines,
over plain TCP sockets, and collects their results.

Usage (on the master computer):
    python sim_master.py --host 0.0.0.0 --port 5000 --num-tasks 12 --num-workers 3

--host 0.0.0.0 means "listen on all network interfaces" (recommended).
Find this machine's LAN IP (e.g. with `ip addr` / `ifconfig` / `ipconfig`)
and give that IP to the workers.
"""

import socket
import threading
import queue
import json
import argparse

from typing import List, Tuple

def recv_message(conn):
    """Read one newline-delimited JSON message from the socket."""
    data = b""
    while not data.endswith(b"\n"):
        chunk = conn.recv(4096)
        if not chunk:
            return None  # peer closed the connection
        data += chunk
    return json.loads(data.decode())

def send_message(conn, obj):
    conn.sendall((json.dumps(obj) + "\n").encode())

# SEARCH: Master's handling of workers occurs here.
def worker_handler(conn: socket.socket, addr, task_queue: queue.Queue, results, results_lock):
    try:
        while True:
            try:
                task = task_queue.get_nowait()
            except queue.Empty:
                break  # no more work left for this worker

            send_message(conn, task)
            result = recv_message(conn)

            if result is None:
                print(f"[MASTER] Worker {addr} disconnected unexpectedly")
                # put the task back so another worker (or a retry) can do it
                task_queue.put(task)
                return
            with results_lock:
                results.append(result)
            print(f"[MASTER] Result from {addr} -> task {task['task_id']}: {result['result']}")

        # No more tasks: tell the worker it's done
        send_message(conn, {"cmd": "done"})
    finally:
        conn.close()
        print(f"[MASTER] Connection to {addr} closed")

def run_master():
    # For debugging and manual set up of the program's options.
    parser = argparse.ArgumentParser(description="Master node: distributes tasks to workers")
    parser.add_argument("--host", default="0.0.0.0", help="Interface to bind on (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=5000, help="Port to listen on (default: 5000)")
    parser.add_argument("--num-tasks", type=int, default=12, help="How many tasks to generate")
    parser.add_argument("--num-workers", type=int, default=3, help="How many workers to wait for before starting")
    args = parser.parse_args()

    # Build the task queue. Replace this with whatever real work items you need.
    task_queue = queue.Queue()
    for i in range(args.num_tasks):
        task_queue.put({"task_id": i, "payload": i})

    results = []
    results_lock = threading.Lock()

    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((args.host, args.port))
    server.listen(args.num_workers)

    print(f"[MASTER] Listening on {args.host}:{args.port}")
    print(f"[MASTER] Waiting for {args.num_workers} worker(s) to connect...")

    # Accept every expected worker BEFORE starting to hand out any tasks,
    # so no worker gets a head start on the others.
    connections: List[Tuple[socket.socket, socket._RetAddress]] = []
    for _ in range(args.num_workers):
        # Wait for worker's incomming connection.
        conn, addr = server.accept()
        connections.append((conn, addr))
        print(f"[MASTER] Worker connected from {addr} ({len(connections)}/{args.num_workers})")

    print("[MASTER] All workers connected. Starting task distribution.\n")

    # PENDING: Handle downed workers and task reassignment.
    threads: List[threading.Thread] = []
    for conn, addr in connections:
        t = threading.Thread(
            target=worker_handler,
            args=(conn, addr, task_queue, results, results_lock),
            daemon=True,
        )

        t.start()
        threads.append(t)

    # Awaits threads to finish (Kinda)
    for t in threads: t.join()

    print("\n[MASTER] All workers finished. Results:")
    for r in sorted(results, key=lambda x: x["task_id"]):
        print(f"  Task {r['task_id']}: {r['result']}")

    server.close()

if __name__ == "__main__":
    run_master()