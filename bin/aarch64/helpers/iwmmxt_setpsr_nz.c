#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define SIMD64_SET(v, n)        ((v != 0) << (32 + (n)))

#define SIMD_NBIT       -1

#define SIMD_ZBIT       -2

uint32_t HELPER(iwmmxt_setpsr_nz)(uint64_t x)
{
    return SIMD64_SET((x == 0), SIMD_ZBIT) |
           SIMD64_SET((x & (1ULL << 63)), SIMD_NBIT);
}

