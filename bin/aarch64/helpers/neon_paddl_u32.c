#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_paddl_u32)(uint64_t a, uint64_t b)
{
    uint32_t low = a + (a >> 32);
    uint32_t high = b + (b >> 32);
    return low + ((uint64_t)high << 32);
}

