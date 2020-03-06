#include <stdint.h>

typedef int32_t target_long;

typedef uint32_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

#define MIPSDSP_RETURN32_8(a, b, c, d)  ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 24) |       \
                                          ((uint32_t)(b) << 16) |       \
                                          ((uint32_t)(c) << 8) |        \
                                          ((uint32_t)(d) & 0xFF)))

#define PRECR_QB_PH(name, a, b)\
target_ulong helper_##name##_qb_ph(target_ulong rs, target_ulong rt) \
{                                                                    \
    uint8_t tempD, tempC, tempB, tempA;                              \
                                                                     \
    tempD = (rs >> a) & MIPSDSP_Q0;                                  \
    tempC = (rs >> b) & MIPSDSP_Q0;                                  \
    tempB = (rt >> a) & MIPSDSP_Q0;                                  \
    tempA = (rt >> b) & MIPSDSP_Q0;                                  \
                                                                     \
    return MIPSDSP_RETURN32_8(tempD, tempC, tempB, tempA);           \
}

PRECR_QB_PH(precrq, 24, 8)

