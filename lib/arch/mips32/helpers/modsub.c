#include <stdint.h>

typedef uint32_t target_ulong;

#define MIPSDSP_LLO 0x00000000FFFFFFFFull

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_Q0  0x000000FF

target_ulong helper_modsub(target_ulong rs, target_ulong rt)
{
    int32_t decr;
    uint16_t lastindex;
    target_ulong rd;

    decr = rt & MIPSDSP_Q0;
    lastindex = (rt >> 8) & MIPSDSP_LO;

    if ((rs & MIPSDSP_LLO) == 0x00000000) {
        rd = (target_ulong)lastindex;
    } else {
        rd = rs - decr;
    }

    return rd;
}

