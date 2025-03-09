#include "jove_sin.c"

double _jove_tan(double x) {
  return _jove_sin(x) / _jove_cos(x);
}
