#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_rhadd_u32)(uint32_t src1, uint32_t src2)
{
    uint32_t dest;

    dest = (src1 >> 1) + (src2 >> 1);
    if ((src1 | src2) & 1)
        dest++;
    return dest;
}

