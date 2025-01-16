#include <windows.h>

int main(int argc, char **argv) {
  // Get the handle to the standard output (console)
  HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);

  if (hConsole == INVALID_HANDLE_VALUE) {
    return 1; // Error obtaining the console handle
  }

  // Prepare the text to print
  LPCSTR message = "Hello, Windows console!\n";
  DWORD written;

  // Write the text to the console
  WriteConsoleA(hConsole, message, lstrlenA(message), &written, NULL);

  // If there are command-line arguments, print the first one
  if (argc > 1) {
    WriteConsoleA(hConsole, "First command-line argument: ", 29, &written, NULL);
    WriteConsoleA(hConsole, argv[1], lstrlenA(argv[1]), &written, NULL);
    WriteConsoleA(hConsole, "\n", 1, &written, NULL);
  }

  return 0;
}
