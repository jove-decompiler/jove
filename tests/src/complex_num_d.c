#include <stdio.h>
#include <stdlib.h>
#include <math.h>

typedef double complex_part_t;

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

int main(int argc, char **argv) {
  if (argc != 6) {
    puts("usage: complex-num w x [+-*/] y z");
    return 0;
  }

  struct complex_t a, b;
  a.real = fmod(atof(argv[1]), 8.0);
  a.imag = fmod(atof(argv[2]), 8.0);
  b.real = fmod(atof(argv[4]), 8.0);
  b.imag = fmod(atof(argv[5]), 8.0);

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

void print_complex(struct complex_t c) {
  printf("%f + %f i\n", c.real, c.imag);
}
