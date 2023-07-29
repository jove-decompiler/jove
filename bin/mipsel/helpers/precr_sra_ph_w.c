#include <stdint.h>

typedef int32_t target_long;

typedef uint32_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_RETURN32_16(a, b)       ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 16) |       \
                                          ((uint32_t)(b) & 0xFFFF)))

target_ulong helper_precr_sra_ph_w(uint32_t sa, target_ulong rs,
                                   target_ulong rt)
{
    uint16_t tempB, tempA;

    tempB = ((int32_t)rt >> sa) & MIPSDSP_LO;
    tempA = ((int32_t)rs >> sa) & MIPSDSP_LO;

    return MIPSDSP_RETURN32_16(tempB, tempA);
}

