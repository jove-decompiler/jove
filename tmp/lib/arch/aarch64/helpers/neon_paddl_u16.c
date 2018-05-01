#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_paddl_u16)(uint64_t a, uint64_t b)
{
    uint64_t tmp;
    uint64_t tmp2;

    tmp = a & 0x0000ffff0000ffffull;
    tmp += (a >> 16) & 0x0000ffff0000ffffull;
    tmp2 = b & 0xffff0000ffff0000ull;
    tmp2 += (b << 16) & 0xffff0000ffff0000ull;
    return    ( tmp         & 0xffff)
            | ((tmp  >> 16) & 0xffff0000ull)
            | ((tmp2 << 16) & 0xffff00000000ull)
            | ( tmp2        & 0xffff000000000000ull);
}

