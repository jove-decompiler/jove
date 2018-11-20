#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_rshl_s64)(uint64_t valop, uint64_t shiftop)
{
    int8_t shift = (int8_t)shiftop;
    int64_t val = valop;
    if ((shift >= 64) || (shift <= -64)) {
        val = 0;
    } else if (shift < 0) {
        val >>= (-shift - 1);
        if (val == INT64_MAX) {
            /* In this case, it means that the rounding constant is 1,
             * and the addition would overflow. Return the actual
             * result directly.  */
            val = 0x4000000000000000LL;
        } else {
            val++;
            val >>= 1;
        }
    } else {
        val <<= shift;
    }
    return val;
}

