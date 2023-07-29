#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <stddef.h>

#define HELPER(name) glue(helper_, name)

static inline uint64_t do_uqrshl_d(uint64_t src, int64_t shift,
                                   bool round, uint32_t *sat)
{
    if (shift <= -(64 + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < 64) {
        uint64_t val = src << shift;
        if (!sat || val >> shift == src) {
            return val;
        }
    } else if (!sat || src == 0) {
        return 0;
    }

    *sat = 1;
    return UINT64_MAX;
}

uint64_t HELPER(neon_rshl_u64)(uint64_t val, uint64_t shift)
{
    return do_uqrshl_d(val, (int8_t)shift, true, NULL);
}

