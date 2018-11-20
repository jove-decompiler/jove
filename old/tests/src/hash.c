#include <stdio.h>
#include <string.h>
#include <stdlib.h>

__attribute__ ((noinline)) long hash(const char* s);

int main(int argc, char **argv) {
  if (argc != 2) {
    printf("usage: hash string\n");
    return 0;
  }

  return hash(argv[1]);
}

long hash(const char* s) {
  long h = 0;
  for (;;) {
    char ch = *s;
    if (ch == '\0')
      break;

    h = 31 * h + ch;

    ++s;
  }

  return h;
}
