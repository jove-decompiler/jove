#include <stdint.h>

typedef int64_t target_long;

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

#define SHIFT_W(name, func) \
target_ulong helper_##name##_w(target_ulong sa, target_ulong rt) \
{                                                                       \
    uint32_t temp;                                                      \
                                                                        \
    sa = sa & 0x1F;                                                     \
    temp = mipsdsp_##func(rt, sa);                                      \
                                                                        \
    return (target_long)(int32_t)temp;                                  \
}

SHIFT_W(shra_r, rnd32_rashift)

