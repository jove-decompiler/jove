#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_insr)(uint64_t x, uint32_t a, uint32_t b, uint32_t n)
{
    x &= ~((uint64_t) b << n);
    x |= (uint64_t) (a & b) << n;
    return x;
}

