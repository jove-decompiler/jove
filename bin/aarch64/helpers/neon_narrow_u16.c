#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_narrow_u16)(uint64_t x)
{
    return (x & 0xffffu) | ((x >> 16) & 0xffff0000u);
}

