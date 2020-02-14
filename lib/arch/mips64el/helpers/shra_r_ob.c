#include <stdint.h>

typedef uint64_t target_ulong;

static inline uint8_t mipsdsp_rnd8_rashift(uint8_t a, uint8_t s)
{
    uint32_t temp;

    if (s == 0) {
        temp = (uint32_t)a << 1;
    } else {
        temp = (int32_t)(int8_t)a >> (s - 1);
    }

    return (temp + 1) >> 1;
}

#define MIPSDSP_Q0  0x000000FF

#define SHIFT_OB(name, func) \
target_ulong helper_##name##_ob(target_ulong rt, target_ulong sa) \
{                                                                        \
    int i;                                                               \
    uint8_t rt_t[8];                                                     \
    uint64_t temp;                                                       \
                                                                         \
    sa = sa & 0x07;                                                      \
    temp = 0;                                                            \
                                                                         \
    for (i = 0; i < 8; i++) {                                            \
        rt_t[i] = (rt >> (8 * i)) & MIPSDSP_Q0;                          \
        rt_t[i] = mipsdsp_##func(rt_t[i], sa);                           \
        temp |= (uint64_t)rt_t[i] << (8 * i);                            \
    }                                                                    \
                                                                         \
    return temp;                                                         \
}

SHIFT_OB(shra_r, rnd8_rashift)

