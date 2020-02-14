#include <stdint.h>

typedef int64_t target_long;

typedef uint64_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

#define MIPSDSP_RETURN32_16(a, b)       ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 16) |       \
                                          ((uint32_t)(b) & 0xFFFF)))

#define PRECEU_PH(name, a, b) \
target_ulong helper_preceu_ph_##name(target_ulong rt) \
{                                                     \
    uint16_t tempB, tempA;                            \
                                                      \
    tempB = (rt >> a) & MIPSDSP_Q0;                   \
    tempA = (rt >> b) & MIPSDSP_Q0;                   \
                                                      \
    return MIPSDSP_RETURN32_16(tempB, tempA);         \
}

PRECEU_PH(qbr, 8, 0)

