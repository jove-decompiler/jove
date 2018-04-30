#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_narrow_round_high_u16)(uint64_t x)
{
    x &= 0xffff8000ffff8000ull;
    x += 0x0000800000008000ull;
    return ((x >> 16) & 0xffff) | ((x >> 32) & 0xffff0000);
}

