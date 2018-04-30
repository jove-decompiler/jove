#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_widen_s16)(uint32_t x)
{
    uint64_t high = (int16_t)(x >> 16);
    return ((uint32_t)(int16_t)x) | (high << 32);
}

