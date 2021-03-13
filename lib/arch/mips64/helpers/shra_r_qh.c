#include <stdint.h>

typedef uint64_t target_ulong;

static inline uint16_t mipsdsp_rnd16_rashift(uint16_t a, uint8_t s)
{
    uint32_t temp;

    if (s == 0) {
        temp = (uint32_t)a << 1;
    } else {
        temp = (int32_t)(int16_t)a >> (s - 1);
    }

    return (temp + 1) >> 1;
}

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

#define SHIFT_QH(name, func) \
target_ulong helper_##name##_qh(target_ulong rt, target_ulong sa) \
{                                                                 \
    uint16_t rt3, rt2, rt1, rt0;                                  \
                                                                  \
    sa = sa & 0x0F;                                               \
                                                                  \
    MIPSDSP_SPLIT64_16(rt, rt3, rt2, rt1, rt0);                   \
                                                                  \
    rt3 = mipsdsp_##func(rt3, sa);                                \
    rt2 = mipsdsp_##func(rt2, sa);                                \
    rt1 = mipsdsp_##func(rt1, sa);                                \
    rt0 = mipsdsp_##func(rt0, sa);                                \
                                                                  \
    return MIPSDSP_RETURN64_16(rt3, rt2, rt1, rt0);               \
}

SHIFT_QH(shra_r, rnd16_rashift)

