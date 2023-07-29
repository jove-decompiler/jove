#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(iwmmxt_msbb)(uint64_t x)
{
    return
        ((x >> 7) & 0x01) | ((x >> 14) & 0x02) |
        ((x >> 21) & 0x04) | ((x >> 28) & 0x08) |
        ((x >> 35) & 0x10) | ((x >> 42) & 0x20) |
        ((x >> 49) & 0x40) | ((x >> 56) & 0x80);
}

