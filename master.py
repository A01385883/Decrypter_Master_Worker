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

import sys
import socket

import queue
import json
import argparse

import selectors
import asyncio
import threading

import time

# Type Enforcement
from collections.abc import Collection, Callable
from typing import List, Tuple, Dict, Annotated

from enum import Enum
from dataclasses import dataclass, field

# Colored-Logging for clear debugging. 

class Tcolors():
    CYAN = '\033[96m'
    MAGENTA = '\033[95m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    ENDC = '\033[0m'

class LogPriority(Enum):
    DEBG = "debug" 
    INFO = "info"
    WARN = "warn"
    ERR  = "error"

# Worker socket conn. state.

class ConnState(Enum):
    IDLE      = "idle"
    BUSY      = "busy"

# Entities config.

@dataclass
class NetConfig:
    host: str
    port: int

@dataclass
class Worker:
    worker_id: str
    writer: asyncio.StreamWriter

# SECTION --- MASTER NODE

class MasterNode:
    def __init__(self, mhost_, mport_, nworkers_: int, ntasks_: int):
        self.net_config = NetConfig(host=mhost_, port=mport_)

        # Save tasks
        self.task_queue = asyncio.Queue(ntasks_)

        # PENDING Worker instances 
        self.workers = dict()

    def log_master(self, msg_: str, priority_ = LogPriority.INFO) -> None:
            e_name = "MASTER"
            if priority_ == LogPriority.ERR:
                print(f"{Tcolors.RED}[{e_name}] (Err) {msg_}{Tcolors.ENDC}")
            elif priority_ == LogPriority.WARN:
                print(f"{Tcolors.YELLOW}[{e_name}] (Warn) {msg_}{Tcolors.ENDC}")
            elif priority_ == LogPriority.DEBG:
                print(f"{Tcolors.MAGENTA}[{e_name}] (Debug) {msg_}{Tcolors.ENDC}")
            else:
                print(f"[{e_name}] (Info) {msg_}")

    def info(self) -> None:
        print(f"\n===== START MASTER NODE INFO =====\n")
        print(f"Addr: {self.net_config.host}:{str(self.net_config.port)}")
        print(f"Cap : {len(self.workers)}")
        print(f"\n===== END MASTER NODE INFO =====\n")

    async def add_task(self, task: Dict[str, int]) -> None:
        await self.task_queue.put(task)

    # With asynchronicity
    async def handle_worker(self, r: asyncio.StreamReader, w: asyncio.StreamWriter):
        address = w.get_extra_info("peername")
        self.log_master(f"Worker Connected: {address}", LogPriority.DEBG)

        # Implement a registration method for the worker.

        # worker_id = (await r.readline()).decode().strip()

        # self.workers[worker_id] = Worker(
        #     worker_id=worker_id,
        #     writer=w,
        # )

        try:
            while True or not self.task_queue.empty():
                # Receive echo message from worker to confirm conn. 
                data = await r.read(4096)

                # Client disconnection
                if not data:
                    break

                self.log_master(f"Received from {address}: {data.decode('utf-8')}")

                # task = await self.task_queue.get()
                # self.log_master(f"Sending task {task} to {address}", LogPriority.INFO)

        except (ConnectionResetError, BrokenPipeError):
            self.log_master(
                # f"{worker_id} had an error, it was disconnected.", 
                f"{address} had an error, forcefully disconnected",
                LogPriority.ERR
            )
        finally:
            self.log_master(
                f"{address} has disconnected",
                LogPriority.WARN
            )

            # self.workers.pop(worker_id, None)
            w.close()
            await w.wait_closed()

    async def run_server(self) -> None:
        server = await asyncio.start_server(
            self.handle_worker, 
            self.net_config.host, 
            self.net_config.port
        )

        addr = server.sockets[0].getsockname()
        self.log_master(f"Serving on {addr}", LogPriority.DEBG)

        await master.add_task({ "Root" : 441 })
        await master.add_task({ "Root" : 484 })
        await master.add_task({ "Root" : 169 })

        try:
            async with server:
                await server.serve_forever()
        except Exception as e:
            self.log_master(f"Error ocurred within server runtime: {e}", LogPriority.ERR)
            sys.exit(1)
        finally:
            self.log_master("Server has closed.", LogPriority.WARN)

# Function to create a new MasterNode instance.
def create_master() -> MasterNode:
    parser = argparse.ArgumentParser(description="Task distribution node")

    parser.add_argument("--host", default="0.0.0.0")
    parser.add_argument("--port", type=int, default=5000)
    parser.add_argument("--num-tasks", type=int, default=12)
    parser.add_argument("--num-workers", type=int, default=3)

    args = parser.parse_args()

    return MasterNode(
        mhost_=args.host,
        mport_=args.port,
        nworkers_=args.num_workers,
        ntasks_=args.num_tasks
    )

# On execution.
if __name__ == '__main__':
    master = create_master()
    master.info()

    asyncio.run(master.run_server())

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

    amount_of_tasks: int = args.num_tasks

    for i in range(amount_of_tasks):
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

    print(f"Tasks completed succesfully: {len(results)} / {amount_of_tasks}")

    server.close()