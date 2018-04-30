#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_shl_s64)(uint64_t valop, uint64_t shiftop)
{
    int8_t shift = (int8_t)shiftop;
    int64_t val = valop;
    if (shift >= 64) {
        val = 0;
    } else if (shift <= -64) {
        val >>= 63;
    } else if (shift < 0) {
        val >>= -shift;
    } else {
        val <<= shift;
    }
    return val;
}

