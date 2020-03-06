#include <stdint.h>

typedef int32_t target_long;

typedef uint32_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

target_ulong helper_precr_sra_r_ph_w(uint32_t sa,
                                     target_ulong rs, target_ulong rt)
{
    uint64_t tempB, tempA;

    /* If sa = 0, then (sa - 1) = -1 will case shift error, so we need else. */
    if (sa == 0) {
        tempB = (rt & MIPSDSP_LO) << 1;
        tempA = (rs & MIPSDSP_LO) << 1;
    } else {
        tempB = ((int32_t)rt >> (sa - 1)) + 1;
        tempA = ((int32_t)rs >> (sa - 1)) + 1;
    }
    rt = (((tempB >> 1) & MIPSDSP_LO) << 16) | ((tempA >> 1) & MIPSDSP_LO);

    return (target_long)(int32_t)rt;
}

