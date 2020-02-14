#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

#define MIPSDSP_SPLIT32_8(num, a, b, c, d)  \
    do {                                    \
        a = ((num) >> 24) & MIPSDSP_Q0;     \
        b = ((num) >> 16) & MIPSDSP_Q0;     \
        c = ((num) >> 8) & MIPSDSP_Q0;      \
        d = (num) & MIPSDSP_Q0;             \
    } while (0)

#define SUBUH_QB(name, var) \
target_ulong helper_##name##_qb(target_ulong rs, target_ulong rt) \
{                                                                 \
    uint8_t rs3, rs2, rs1, rs0;                                   \
    uint8_t rt3, rt2, rt1, rt0;                                   \
    uint8_t tempD, tempC, tempB, tempA;                           \
                                                                  \
    MIPSDSP_SPLIT32_8(rs, rs3, rs2, rs1, rs0);                    \
    MIPSDSP_SPLIT32_8(rt, rt3, rt2, rt1, rt0);                    \
                                                                  \
    tempD = ((uint16_t)rs3 - (uint16_t)rt3 + var) >> 1;           \
    tempC = ((uint16_t)rs2 - (uint16_t)rt2 + var) >> 1;           \
    tempB = ((uint16_t)rs1 - (uint16_t)rt1 + var) >> 1;           \
    tempA = ((uint16_t)rs0 - (uint16_t)rt0 + var) >> 1;           \
                                                                  \
    return ((uint32_t)tempD << 24) | ((uint32_t)tempC << 16) |    \
        ((uint32_t)tempB << 8) | ((uint32_t)tempA);               \
}

SUBUH_QB(subuh, 0)

