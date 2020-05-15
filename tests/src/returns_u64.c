#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <inttypes.h>

typedef uint64_t (*ABIFnTy)(int);

__attribute__((noinline))
uint64_t foo(int argc) {
  int32_t x = argc * rand();
  int32_t y = argc * rand();

  int64_t res = x;
  res |= ((int64_t)y << 32);

  return res;
}

__attribute__((noinline))
void bar(ABIFnTy f) {
  printf("f(0)=%" PRIx64 "\n", f(0));
}

int main(int argc, char **argv) {
  srand(1234);

  bar(foo);

  uint64_t u64 = foo(argc);
  printf("u64=%" PRIx64 "\n", u64);

  return 0;
}
