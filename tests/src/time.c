#include <stdint.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

int main(int argc, char **argv) {
  time_t result = time(NULL);

#if 0
  printf("%s%ju secs since the Epoch\n",
         aksctime(localtime(&result)),
         (uintmax_t)result);
#else
  printf("time(NULL) = %lu\n",
         result);
#endif

  return 0;
}
