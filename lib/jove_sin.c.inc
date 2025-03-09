#include "jove_cos.c.inc"

double _jove_sin(double x) {
  return _jove_cos(CONST_PI / 2.0 - x);
}
