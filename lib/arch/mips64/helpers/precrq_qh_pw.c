#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_RETURN64_16(a, b, c, d) (((uint64_t)(a) << 48) |        \
                                         ((uint64_t)(b) << 32) |        \
                                         ((uint64_t)(c) << 16) |        \
                                         (uint64_t)(d))

target_ulong helper_precrq_qh_pw(target_ulong rs, target_ulong rt)
{
    uint16_t tempD, tempC, tempB, tempA;

    tempD = (rs >> 48) & MIPSDSP_LO;
    tempC = (rs >> 16) & MIPSDSP_LO;
    tempB = (rt >> 48) & MIPSDSP_LO;
    tempA = (rt >> 16) & MIPSDSP_LO;

    return MIPSDSP_RETURN64_16(tempD, tempC, tempB, tempA);
}

