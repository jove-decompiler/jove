#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

#define MIPSDSP_RETURN64_16(a, b, c, d) (((uint64_t)(a) << 48) |        \
                                         ((uint64_t)(b) << 32) |        \
                                         ((uint64_t)(c) << 16) |        \
                                         (uint64_t)(d))

#define PRECEU_QH(name, a, b, c, d) \
target_ulong helper_preceu_qh_##name(target_ulong rt)        \
{                                                            \
    uint16_t tempD, tempC, tempB, tempA;                     \
                                                             \
    tempD = (rt >> a) & MIPSDSP_Q0;                          \
    tempC = (rt >> b) & MIPSDSP_Q0;                          \
    tempB = (rt >> c) & MIPSDSP_Q0;                          \
    tempA = (rt >> d) & MIPSDSP_Q0;                          \
                                                             \
    return MIPSDSP_RETURN64_16(tempD, tempC, tempB, tempA);  \
}

PRECEU_QH(obla, 56, 40, 24, 8)

