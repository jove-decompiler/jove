#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_widen_s8)(uint32_t x)
{
    uint64_t tmp;
    uint64_t ret;
    ret = (uint16_t)(int8_t)x;
    tmp = (uint16_t)(int8_t)(x >> 8);
    ret |= tmp << 16;
    tmp = (uint16_t)(int8_t)(x >> 16);
    ret |= tmp << 32;
    tmp = (uint16_t)(int8_t)(x >> 24);
    ret |= tmp << 48;
    return ret;
}

