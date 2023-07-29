#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(iwmmxt_msbl)(uint64_t x)
{
    return ((x >> 31) & 0x01) | ((x >> 62) & 0x02);
}

