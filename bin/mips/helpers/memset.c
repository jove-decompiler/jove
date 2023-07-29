#include <string.h>

void *helper_memset(void *s, int c, size_t n) {
  return __builtin_memset(s, c, n);
}
