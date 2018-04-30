#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_tbl)(uint32_t ireg, uint32_t def, void *vn,
                          uint32_t maxindex)
{
    uint32_t val, shift;
    uint64_t *table = vn;

    val = 0;
    for (shift = 0; shift < 32; shift += 8) {
        uint32_t index = (ireg >> shift) & 0xff;
        if (index < maxindex) {
            uint32_t tmp = (table[index >> 3] >> ((index & 7) << 3)) & 0xff;
            val |= tmp << shift;
        } else {
            val |= def & (0xff << shift);
        }
    }
    return val;
}

