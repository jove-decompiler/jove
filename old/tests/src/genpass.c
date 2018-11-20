#include "librand.h"
#include <stdlib.h>
#include <stdio.h>
#include <time.h>

int main(int argc, char** argv) {
  fprintf(stdout, "%lu\n", librand_get());
  librand_dump_seed();
  fprintf(stderr, "%lu\n", librand_get());
  librand_seed = time(NULL);
  return 0;
}
