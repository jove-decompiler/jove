#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_negl_u16)(uint64_t x)
{
    uint16_t tmp;
    uint64_t result;
    result = (uint16_t)-x;
    tmp = -(x >> 16);
    result |= (uint64_t)tmp << 16;
    tmp = -(x >> 32);
    result |= (uint64_t)tmp << 32;
    tmp = -(x >> 48);
    result |= (uint64_t)tmp << 48;
    return result;
}

