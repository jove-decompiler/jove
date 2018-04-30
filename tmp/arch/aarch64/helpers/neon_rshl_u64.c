#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_rshl_u64)(uint64_t val, uint64_t shiftop)
{
    int8_t shift = (uint8_t)shiftop;
    if (shift >= 64 || shift < -64) {
        val = 0;
    } else if (shift == -64) {
        /* Rounding a 1-bit result just preserves that bit.  */
        val >>= 63;
    } else if (shift < 0) {
        val >>= (-shift - 1);
        if (val == UINT64_MAX) {
            /* In this case, it means that the rounding constant is 1,
             * and the addition would overflow. Return the actual
             * result directly.  */
            val = 0x8000000000000000ULL;
        } else {
            val++;
            val >>= 1;
        }
    } else {
        val <<= shift;
    }
    return val;
}

