#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(iwmmxt_msbw)(uint64_t x)
{
    return
        ((x >> 15) & 0x01) | ((x >> 30) & 0x02) |
        ((x >> 45) & 0x04) | ((x >> 52) & 0x08);
}

