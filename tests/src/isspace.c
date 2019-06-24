#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

int main(int argc, char **argv) {
  if (argc != 2)
    return 1;

#if 0
  const char *string = argv[1];
  printf("string=%s\n", string);
#endif

  printf("isspace('%c')=%d\n", argv[1][0], isspace(argv[1][0]));

  return 0;
}
