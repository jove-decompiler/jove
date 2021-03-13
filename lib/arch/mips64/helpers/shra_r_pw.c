#include <stdint.h>

typedef uint64_t target_ulong;

static inline uint32_t mipsdsp_rnd32_rashift(uint32_t a, uint8_t s)
{
    int64_t temp;

    if (s == 0) {
        temp = (uint64_t)a << 1;
    } else {
        temp = (int64_t)(int32_t)a >> (s - 1);
    }
    temp += 1;

    return (temp >> 1) & 0xFFFFFFFFull;
}

#define MIPSDSP_LLO 0x00000000FFFFFFFFull

#define MIPSDSP_SPLIT64_32(num, a, b)       \
    do {                                    \
        a = ((num) >> 32) & MIPSDSP_LLO;    \
        b = (num) & MIPSDSP_LLO;            \
    } while (0)

#define MIPSDSP_RETURN64_32(a, b)       (((uint64_t)(a) << 32) | (uint64_t)(b))

#define SHIFT_PW(name, func) \
target_ulong helper_##name##_pw(target_ulong rt, target_ulong sa) \
{                                                                 \
    uint32_t rt1, rt0;                                            \
                                                                  \
    sa = sa & 0x1F;                                               \
    MIPSDSP_SPLIT64_32(rt, rt1, rt0);                             \
                                                                  \
    rt1 = mipsdsp_##func(rt1, sa);                                \
    rt0 = mipsdsp_##func(rt0, sa);                                \
                                                                  \
    return MIPSDSP_RETURN64_32(rt1, rt0);                         \
}

SHIFT_PW(shra_r, rnd32_rashift)

