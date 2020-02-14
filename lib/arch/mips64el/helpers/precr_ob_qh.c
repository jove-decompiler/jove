#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

target_ulong helper_precr_ob_qh(target_ulong rs, target_ulong rt)
{
    uint8_t rs6, rs4, rs2, rs0;
    uint8_t rt6, rt4, rt2, rt0;
    uint64_t temp;

    rs6 = (rs >> 48) & MIPSDSP_Q0;
    rs4 = (rs >> 32) & MIPSDSP_Q0;
    rs2 = (rs >> 16) & MIPSDSP_Q0;
    rs0 = rs & MIPSDSP_Q0;
    rt6 = (rt >> 48) & MIPSDSP_Q0;
    rt4 = (rt >> 32) & MIPSDSP_Q0;
    rt2 = (rt >> 16) & MIPSDSP_Q0;
    rt0 = rt & MIPSDSP_Q0;

    temp = ((uint64_t)rs6 << 56) | ((uint64_t)rs4 << 48) |
           ((uint64_t)rs2 << 40) | ((uint64_t)rs0 << 32) |
           ((uint64_t)rt6 << 24) | ((uint64_t)rt4 << 16) |
           ((uint64_t)rt2 << 8) | (uint64_t)rt0;

    return temp;
}

