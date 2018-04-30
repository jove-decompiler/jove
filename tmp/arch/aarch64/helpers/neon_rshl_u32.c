#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_rshl_u32)(uint32_t val, uint32_t shiftop)
{
    uint32_t dest;
    int8_t shift = (int8_t)shiftop;
    if (shift >= 32 || shift < -32) {
        dest = 0;
    } else if (shift == -32) {
        dest = val >> 31;
    } else if (shift < 0) {
        uint64_t big_dest = ((uint64_t)val + (1 << (-1 - shift)));
        dest = big_dest >> -shift;
    } else {
        dest = val << shift;
    }
    return dest;
}

