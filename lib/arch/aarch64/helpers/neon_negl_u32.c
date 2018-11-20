#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_negl_u32)(uint64_t x)
{
    uint32_t low = -x;
    uint32_t high = -(x >> 32);
    return low | ((uint64_t)high << 32);
}

