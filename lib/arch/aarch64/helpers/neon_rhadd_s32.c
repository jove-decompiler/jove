#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

int32_t HELPER(neon_rhadd_s32)(int32_t src1, int32_t src2)
{
    int32_t dest;

    dest = (src1 >> 1) + (src2 >> 1);
    if ((src1 | src2) & 1)
        dest++;
    return dest;
}

