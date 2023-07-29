#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_narrow_u8)(uint64_t x)
{
    return (x & 0xffu) | ((x >> 8) & 0xff00u) | ((x >> 16) & 0xff0000u)
           | ((x >> 24) & 0xff000000u);
}

