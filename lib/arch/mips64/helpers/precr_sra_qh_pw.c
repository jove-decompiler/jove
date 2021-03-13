#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_SPLIT64_16(num, a, b, c, d)  \
    do {                                     \
        a = ((num) >> 48) & MIPSDSP_LO;      \
        b = ((num) >> 32) & MIPSDSP_LO;      \
        c = ((num) >> 16) & MIPSDSP_LO;      \
        d = (num) & MIPSDSP_LO;              \
    } while (0)

#define MIPSDSP_RETURN64_16(a, b, c, d) (((uint64_t)(a) << 48) |        \
                                         ((uint64_t)(b) << 32) |        \
                                         ((uint64_t)(c) << 16) |        \
                                         (uint64_t)(d))

#define PRECR_QH_PW(name, var)                                        \
target_ulong helper_precr_##name##_qh_pw(target_ulong rs,             \
                                         target_ulong rt,             \
                                         uint32_t sa)                 \
{                                                                     \
    uint16_t rs3, rs2, rs1, rs0;                                      \
    uint16_t rt3, rt2, rt1, rt0;                                      \
    uint16_t tempD, tempC, tempB, tempA;                              \
                                                                      \
    MIPSDSP_SPLIT64_16(rs, rs3, rs2, rs1, rs0);                       \
    MIPSDSP_SPLIT64_16(rt, rt3, rt2, rt1, rt0);                       \
                                                                      \
    if (sa == 0) {                                                    \
        tempD = rt2 << var;                                           \
        tempC = rt0 << var;                                           \
        tempB = rs2 << var;                                           \
        tempA = rs0 << var;                                           \
    } else {                                                          \
        tempD = (((int16_t)rt3 >> sa) + var) >> var;                  \
        tempC = (((int16_t)rt1 >> sa) + var) >> var;                  \
        tempB = (((int16_t)rs3 >> sa) + var) >> var;                  \
        tempA = (((int16_t)rs1 >> sa) + var) >> var;                  \
    }                                                                 \
                                                                      \
    return MIPSDSP_RETURN64_16(tempD, tempC, tempB, tempA);           \
}

PRECR_QH_PW(sra, 0)

