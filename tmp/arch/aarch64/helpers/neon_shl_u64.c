#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_shl_u64)(uint64_t val, uint64_t shiftop)
{
    int8_t shift = (int8_t)shiftop;
    if (shift >= 64 || shift <= -64) {
        val = 0;
    } else if (shift < 0) {
        val >>= -shift;
    } else {
        val <<= shift;
    }
    return val;
}

