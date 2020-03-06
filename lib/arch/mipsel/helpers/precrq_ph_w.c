#include <stdint.h>

typedef int32_t target_long;

typedef uint32_t target_ulong;

#define MIPSDSP_HI  0xFFFF0000

#define MIPSDSP_RETURN32_16(a, b)       ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 16) |       \
                                          ((uint32_t)(b) & 0xFFFF)))

target_ulong helper_precrq_ph_w(target_ulong rs, target_ulong rt)
{
    uint16_t tempB, tempA;

    tempB = (rs & MIPSDSP_HI) >> 16;
    tempA = (rt & MIPSDSP_HI) >> 16;

    return MIPSDSP_RETURN32_16(tempB, tempA);
}

