"""
sim_worker.py

Connects to sim_master.py over TCP, pulls tasks one at a time, does some
(simulated) work, and sends the result back.

Usage (on each worker computer):
    python sim_worker.py --host <MASTER_LAN_IP> --port 5000
"""

import sys

import socket
import json
import argparse
import time
import random

import asyncio

from collections.abc import Collection
from typing import List, Tuple, Any

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

# Entities config.

@dataclass
class NetConfig:
    host: str
    port: int

class WorkerNode:
    def __init__(self, mhost_, mport_: int):
        self.net_config = NetConfig(host=mhost_, port=mport_)

    def log_worker(self, msg_: str, priority_ = LogPriority.INFO) -> None:
        e_name = "WORKER"
        if priority_ == LogPriority.ERR:
            print(f"{Tcolors.RED}[{e_name}] (Err) {msg_}{Tcolors.ENDC}")
        elif priority_ == LogPriority.WARN:
            print(f"{Tcolors.YELLOW}[{e_name}] (Warn) {msg_}{Tcolors.ENDC}")
        elif priority_ == LogPriority.DEBG:
            print(f"{Tcolors.MAGENTA}[{e_name}] (Debug) {msg_}{Tcolors.ENDC}")
        else:
            print(f"[{e_name}] (Info) {msg_}")

    def info(self) -> None:
        print(f"\n===== START WORKER NODE INFO =====\n")
        print(f"Connecting TO: ")
        print(f" - Addr: {self.net_config.host}:{str(self.net_config.port)}")
        print(f"\n===== END WORKER NODE INFO =====\n")

    async def execute_task(self, r: asyncio.StreamReader, w: asyncio.StreamWriter) -> None:
        msg = "Hello, asyncio!"
        
        w.write(msg.encode("utf-8"))
        await w.drain()

        raw_data = await r.read(4096)
        resp = raw_data.decode('utf-8')

        self.log_worker(f"Got response: {resp}")

    async def run_client(self):
        r, w = await asyncio.open_connection(self.net_config.host, self.net_config.port)

        try: 
            await self.execute_task(r, w)
        except Exception as e:
            self.log_worker(f"Got an error while running client: {e}", LogPriority.ERR)
            sys.exit(1)
        finally:
            self.log_worker("Closing client connection", LogPriority.WARN)

        w.close()
        await w.wait_closed()
        
def create_worker() -> WorkerNode:
    parser = argparse.ArgumentParser(description="Task execution node")

    parser.add_argument("--host", required=True)
    parser.add_argument("--port", type=int, default=5000)

    args = parser.parse_args()

    return WorkerNode(
        mhost_=args.host,
        mport_=args.port,
    )


if __name__ == "__main__":
    worker = create_worker()
    worker.info()

    # python 3.7 or newer
    asyncio.run(worker.run_client())

    # python 3.0 to 3.6.9
    # loop = asyncio.get_event_loop()
    # loop.run_until_complete(worker.run_client())



# FIX: Ambiguous return value type.
def recv_message(sock: socket.socket) -> Any:
    data = b""
    while not data.endswith(b"\n"):
        chunk = sock.recv(4096)
        if not chunk:
            return None
        data += chunk
    return json.loads(data.decode())

# FIX: Ambiguous sent 'obj' type, can define through pydantic or .
def send_message(sock: socket.socket, obj: Any):
    sock.sendall((json.dumps(obj) + "\n").encode())

# PENDING: Task assigned to solve goes here. Implement the Brute-force solution.
# FIX: Ambiguous return value type.
def simulate_task(payload: Any):
    """Placeholder for real work. Swap this out for your actual computation."""
    time.sleep(random.uniform(0.5, 2.0))
    return payload ** 2

def main():
    parser = argparse.ArgumentParser(description="Worker node: processes tasks from the master")
    parser.add_argument("--host", required=True, help="Master's IP address")
    parser.add_argument("--port", type=int, default=5000, help="Master's port (default: 5000)")
    args = parser.parse_args()

    sock: socket.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
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
