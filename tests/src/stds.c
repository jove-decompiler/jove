#include <stdio.h>

int main(int argc, char **argv) {
  if (argc != 3)
    return 1;

  if (stdout) fprintf(stdout, "stdout: %s\n", argv[1]);
  if (stderr) fprintf(stderr, "stderr: %s\n", argv[2]);

  return 0;
}
