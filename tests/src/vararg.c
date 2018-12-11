#include <stdlib.h>
#include <stdio.h>
#include <stdarg.h>

#define NOINL __attribute__ ((noinline))

NOINL void foo(const char *fmt, ...);

NOINL void ltos(char *out, long I);

NOINL void print_string(const char *);
NOINL void print_int(int);
NOINL void print_char(char);

int main(int argc, char **argv) {
  if (argc != 2) {
    puts("usage: vararg NUMARGS");
    return 0;
  }

  int n = atoi(argv[1]);
  switch (n) {
  case 0:
    break;

  case 1: {
    const char *fmt = "s";
    const char *arg1 = "Hello, world";
    foo(fmt, arg1);
    break;
  }
  case 2: {
    const char *fmt = "sd";
    const char *arg1 = "Hello, world";
    int arg2 = rand();
    foo(fmt, arg1, arg2);
    break;
  }

  case 3: {
    const char *fmt = "ddd";
    int arg1 = rand();
    int arg2 = rand();
    int arg3 = rand();
    foo(fmt, arg1, arg2, arg3);
    break;
  }

  default:
    return 1;
  }

  return 0;
}

// The function foo takes a string of format characters and prints out the argument associated with each format character based on the type.
void foo(const char *fmt, ...) {
  va_list ap;
  int d;
  char c;
  const char *s;

  va_start(ap, fmt);
  while (*fmt)
    switch (*fmt++) {
    case 's': /* string */
      s = va_arg(ap, const char *);
      print_string(s);
      break;
    case 'd': /* int */
      d = va_arg(ap, int);
      print_int(d);
      break;
    case 'c': /* char */
      /* need a cast here since va_arg only
         takes fully promoted types */
      c = (char)va_arg(ap, int);
      print_char(c);
      break;
    default:
      __builtin_unreachable();
    }
  va_end(ap);
}

void print_string(const char *s) {
  puts(s);
}

void print_int(int d) {
  char buff[65];
  ltos(buff, d);

  puts(buff);
}

void print_char(char c) {
  char s[2] = {c, '\0'};

  puts(s);
}

void ltos(char *out, long I) {
  // First, check for a zero value and just short circuit the logic below.
  if (I == 0) {
    *out++ = '0';
    *out++ = '\0';
    return;
  }

  const unsigned Radix = 10;

  static const char Digits[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";

  char Buffer[65];
  char *const BufPtrEnd = &Buffer[sizeof(Buffer)];
  char *BufPtr = BufPtrEnd;

  unsigned long N;
  if (I >= 0) {
    N = (unsigned long)I;
  } else {
    *out++ = '-';
    N = -(unsigned long)I;
  }

  while (N) {
    *--BufPtr = Digits[N % Radix];
    N /= Radix;
  }

  for (char *p = BufPtr; p != BufPtrEnd; ++p)
    *out++ = *p;

  *out++ = '\0';
}
