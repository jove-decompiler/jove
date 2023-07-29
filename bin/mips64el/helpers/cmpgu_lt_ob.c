#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_Q0  0x000000FF

static inline int32_t mipsdsp_cmpu_lt(uint32_t a, uint32_t b)
{
    return a < b;
}

#define CMP_HAS_RET(name, func, split_num, filter, bit_size) \
target_ulong helper_##name(target_ulong rs, target_ulong rt) \
{                                                       \
    uint32_t rs_t, rt_t;                                \
    uint8_t cc;                                         \
    uint32_t temp = 0;                                  \
    int i;                                              \
                                                        \
    for (i = 0; i < split_num; i++) {                   \
        rs_t = (rs >> (bit_size * i)) & filter;         \
        rt_t = (rt >> (bit_size * i)) & filter;         \
        cc = mipsdsp_##func(rs_t, rt_t);                \
        temp |= cc << i;                                \
    }                                                   \
                                                        \
    return (target_ulong)temp;                          \
}

CMP_HAS_RET(cmpgu_lt_ob, cmpu_lt, 8, MIPSDSP_Q0, 8)

