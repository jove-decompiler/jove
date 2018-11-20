#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_align)(uint64_t a, uint64_t b, uint32_t n)
{
    a >>= n << 3;
    a |= b << (64 - (n << 3));
    return a;
}

