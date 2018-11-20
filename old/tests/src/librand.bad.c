#include <stdlib.h>
#include <stdio.h>

unsigned long librand_seed = 0xabcd;

unsigned long librand_get() {
  librand_seed += rand();
  return librand_seed;
}

void librand_dump_seed() {
  fprintf(stderr, "%lu\n", librand_seed);
}
