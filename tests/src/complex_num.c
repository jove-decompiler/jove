#include <stdio.h>
#include <stdlib.h>

typedef long complex_part_t;

struct complex_t {
  complex_part_t real;
  complex_part_t imag;
};

#define NOINL __attribute__ ((noinline))

NOINL struct complex_t cn_add(struct complex_t, struct complex_t);
NOINL struct complex_t cn_sub(struct complex_t, struct complex_t);
NOINL struct complex_t cn_mul(struct complex_t, struct complex_t);
NOINL struct complex_t cn_div(struct complex_t, struct complex_t);

NOINL void print_complex(struct complex_t);

NOINL void ltos(char *out, long I);

int main(int argc, char **argv) {
  if (argc != 6) {
    puts("usage: complex-num w x [+-*/] y z");
    return 0;
  }

  struct complex_t a, b;
  a.real = atol(argv[1]);
  a.imag = atol(argv[2]);
  b.real = atol(argv[4]);
  b.imag = atol(argv[5]);

  struct complex_t c;
  switch (argv[3][0]) {
  case '+':
    c = cn_add(a, b);
    break;
  case '-':
    c = cn_sub(a, b);
    break;
  case '*':
    c = cn_mul(a, b);
    break;
  case '/':
    c = cn_div(a, b);
    break;
  default:
    return 1;
  };

  print_complex(c);
  return 0;
}

struct complex_t cn_add(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real + b.real;
  c.imag = a.imag + b.imag;
  return c;
}
struct complex_t cn_sub(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real - b.real;
  c.imag = a.imag - b.imag;
  return c;
}
struct complex_t cn_mul(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  c.real = a.real * b.real - a.imag * b.imag;
  c.imag = a.imag * b.real + a.real * b.imag;
  return c;
}
struct complex_t cn_div(struct complex_t a, struct complex_t b) {
  struct complex_t c;
  complex_part_t denom = b.real * b.real + b.imag * b.imag;
  c.real = (a.real * b.real + a.imag * b.imag) / denom;
  c.imag = (a.imag * b.real - a.real * b.imag) / denom;
  return c;
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

void print_complex(struct complex_t c) {
  {
    char buff[65];
    ltos(buff, c.real);

    fputs(buff, stdout);
  }

  putchar('+');

  {
    char buff[65];
    ltos(buff, c.imag);

    fputs(buff, stdout);
  }

  putchar('i');
  putchar('\n');

}
