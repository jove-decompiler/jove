#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_cls_s32)(uint32_t x)
{
    int count;
    if ((int32_t)x < 0)
        x = ~x;
    for (count = 32; x; count--)
        x = x >> 1;
    return count - 1;
}

