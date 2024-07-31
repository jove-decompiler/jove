#include "jove_cos.c"

double _jove_sin(double x) {
  return _jove_cos(CONST_PI / 2.0 - x);
}
