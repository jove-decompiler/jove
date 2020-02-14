#include <stdint.h>

typedef int64_t target_long;

typedef uint64_t target_ulong;

static inline uint8_t mipsdsp_rshift_u8(uint8_t a, target_ulong mov)
{
    return a >> mov;
}

#define MIPSDSP_Q0  0x000000FF

#define MIPSDSP_SPLIT32_8(num, a, b, c, d)  \
    do {                                    \
        a = ((num) >> 24) & MIPSDSP_Q0;     \
        b = ((num) >> 16) & MIPSDSP_Q0;     \
        c = ((num) >> 8) & MIPSDSP_Q0;      \
        d = (num) & MIPSDSP_Q0;             \
    } while (0)

#define MIPSDSP_RETURN32_8(a, b, c, d)  ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 24) |       \
                                          ((uint32_t)(b) << 16) |       \
                                          ((uint32_t)(c) << 8) |        \
                                          ((uint32_t)(d) & 0xFF)))

#define SHIFT_QB(name, func) \
target_ulong helper_##name##_qb(target_ulong sa, target_ulong rt) \
{                                                                    \
    uint8_t rt3, rt2, rt1, rt0;                                      \
                                                                     \
    sa = sa & 0x07;                                                  \
                                                                     \
    MIPSDSP_SPLIT32_8(rt, rt3, rt2, rt1, rt0);                       \
                                                                     \
    rt3 = mipsdsp_##func(rt3, sa);                                   \
    rt2 = mipsdsp_##func(rt2, sa);                                   \
    rt1 = mipsdsp_##func(rt1, sa);                                   \
    rt0 = mipsdsp_##func(rt0, sa);                                   \
                                                                     \
    return MIPSDSP_RETURN32_8(rt3, rt2, rt1, rt0);                   \
}

SHIFT_QB(shrl, rshift_u8)

