#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <string.h>
#include <inttypes.h>
#include <unistd.h>

typedef uint64_t (*ABIFnTy)(int);

static void _addrtostr(uintptr_t addr, char *dst, size_t n);

__attribute__((noinline))
uint64_t foo(int argc) {
  int32_t x = rand();
  int32_t y = rand();

  int64_t res = x;
  res |= ((int64_t)y << 32);

  return res;
}

__attribute__((noinline))
void bar(ABIFnTy f) {
#if 0
  printf("f(0)=%" PRIx64 "\n", f(0));
#else
  char buff[65];
  _addrtostr(f(0), buff, sizeof(buff));
#if 0
  puts(buff);
#else
  write(1, buff, strlen(buff));
  write(1, "\n", 1);
#endif
#endif
}

int main(int argc, char **argv) {
  srand(argc);

  bar(foo);

  uint64_t u64 = foo(argc);
#if 0
  printf("u64=%" PRIx64 "\n", u64);
#else
  char buff[65];
  _addrtostr(u64, buff, sizeof(buff));
#if 0
  puts(buff);
#else
  write(1, buff, strlen(buff));
  write(1, "\n", 1);
#endif
#endif

  return 0;
}

void _addrtostr(uintptr_t addr, char *Str, size_t n) {
  const unsigned Radix = 16;
  const bool formatAsCLiteral = true;
  const bool Signed = false;

#if 0
  assert((Radix == 10 || Radix == 8 || Radix == 16 || Radix == 2 ||
          Radix == 36) &&
         "Radix should be 2, 8, 10, 16, or 36!");
#endif

  const char *Prefix = "";
  if (formatAsCLiteral) {
    switch (Radix) {
      case 2:
        // Binary literals are a non-standard extension added in gcc 4.3:
        // http://gcc.gnu.org/onlinedocs/gcc-4.3.0/gcc/Binary-constants.html
        Prefix = "0b";
        break;
      case 8:
        Prefix = "0";
        break;
      case 10:
        break; // No prefix
      case 16:
        Prefix = "0x";
        break;
      default: /* invalid radix */
        __builtin_trap();
        __builtin_unreachable();
    }
  }

  // First, check for a zero value and just short circuit the logic below.
  if (addr == 0) {
    while (*Prefix)
      *Str++ = *Prefix++;

    *Str++ = '0';
    *Str++ = '\0'; /* null-terminate */
    return;
  }

  static const char Digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  char Buffer[65];
  char *BufPtr = &Buffer[sizeof(Buffer)];

  uint64_t N = addr;

  while (*Prefix)
    *Str++ = *Prefix++;

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *Ptr = BufPtr; Ptr != &Buffer[sizeof(Buffer)]; ++Ptr)
    *Str++ = *Ptr;

  *Str = '\0';
}
