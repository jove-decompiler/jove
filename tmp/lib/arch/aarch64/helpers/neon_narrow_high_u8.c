#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_narrow_high_u8)(uint64_t x)
{
    return ((x >> 8) & 0xff) | ((x >> 16) & 0xff00)
            | ((x >> 24) & 0xff0000) | ((x >> 32) & 0xff000000);
}

