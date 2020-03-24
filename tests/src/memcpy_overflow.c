#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <signal.h>

extern void call_system();
extern void call_execve();

long double junk[1000] = {1,2,3,4};
long double junk2[1000] = {5,6,7,8};
long double junk3[1000];
long double junk4[1000];

int __attribute__ ((noinline)) use_them(unsigned char *buf, uint32_t sz) {
  int sum = 0;
  for (uint32_t i = 0; i < sz; ++i) {
    printf("got %d\n", buf[i]);
    sum += (int) buf[i];
  }

  return sum;
}

int __attribute__ ((noinline)) vulnerable_function(unsigned char* text, uint32_t sz) {
  unsigned char lil_buf[30];

  memcpy(lil_buf, text, sz);

  return use_them(lil_buf, sizeof(lil_buf));
}

int main(int argc, char** argv) {
  FILE *f = fopen(argv[1], "rb");
  if (!f) {
    perror("file is foobar");
    return 1;
  }

  unsigned char buf[2];
  fread(buf, 1, sizeof(buf), f);
  uint16_t sz = buf[0] | (buf[1] << 8);

  unsigned char *bytes = malloc(sz);
  if (!bytes) {
    return 1;
  }

  fread(bytes, 1, sz, f);
  printf("sz = %d\n", sz);
  printf("%d\n", vulnerable_function(bytes, sz));

  free(bytes);
  fclose(f);

  return 0;
}
