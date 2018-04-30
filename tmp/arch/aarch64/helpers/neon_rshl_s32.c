#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_rshl_s32)(uint32_t valop, uint32_t shiftop)
{
    int32_t dest;
    int32_t val = (int32_t)valop;
    int8_t shift = (int8_t)shiftop;
    if ((shift >= 32) || (shift <= -32)) {
        dest = 0;
    } else if (shift < 0) {
        int64_t big_dest = ((int64_t)val + (1 << (-1 - shift)));
        dest = big_dest >> -shift;
    } else {
        dest = val << shift;
    }
    return dest;
}

