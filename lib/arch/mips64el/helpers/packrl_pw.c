#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LLO 0x00000000FFFFFFFFull

target_ulong helper_packrl_pw(target_ulong rs, target_ulong rt)
{
    uint32_t rs0, rt1;

    rs0 = rs & MIPSDSP_LLO;
    rt1 = (rt >> 32) & MIPSDSP_LLO;

    return ((uint64_t)rs0 << 32) | (uint64_t)rt1;
}

