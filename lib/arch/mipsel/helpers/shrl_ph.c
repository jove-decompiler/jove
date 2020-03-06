#include <stdint.h>

typedef int32_t target_long;

typedef uint32_t target_ulong;

static inline uint16_t mipsdsp_rshift_u16(uint16_t a, target_ulong mov)
{
    return a >> mov;
}

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_SPLIT32_16(num, a, b)       \
    do {                                    \
        a = ((num) >> 16) & MIPSDSP_LO;     \
        b = (num) & MIPSDSP_LO;             \
    } while (0)

#define MIPSDSP_RETURN32_16(a, b)       ((target_long)(int32_t)         \
                                         (((uint32_t)(a) << 16) |       \
                                          ((uint32_t)(b) & 0xFFFF)))

#define SHIFT_PH(name, func) \
target_ulong helper_##name##_ph(target_ulong sa, target_ulong rt) \
{                                                                    \
    uint16_t rth, rtl;                                               \
                                                                     \
    sa = sa & 0x0F;                                                  \
                                                                     \
    MIPSDSP_SPLIT32_16(rt, rth, rtl);                                \
                                                                     \
    rth = mipsdsp_##func(rth, sa);                                   \
    rtl = mipsdsp_##func(rtl, sa);                                   \
                                                                     \
    return MIPSDSP_RETURN32_16(rth, rtl);                            \
}

SHIFT_PH(shrl, rshift_u16)

