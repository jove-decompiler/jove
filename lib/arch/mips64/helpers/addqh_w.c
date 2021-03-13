#define QEMU_BUILD_BUG_ON_STRUCT(x) \
    struct { \
        int:(x) ? -1 : 1; \
    }

#define QEMU_BUILD_BUG_ON_ZERO(x) (sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)) - \
                                   sizeof(QEMU_BUILD_BUG_ON_STRUCT(x)))

#include <stdint.h>

#define QEMU_IS_ARRAY(x) (!__builtin_types_compatible_p(typeof(x), \
                                                        typeof(&(x)[0])))

#define ARRAY_SIZE(x) ((sizeof(x) / sizeof((x)[0])) + \
                       QEMU_BUILD_BUG_ON_ZERO(!QEMU_IS_ARRAY(x)))

typedef int64_t target_long;

typedef uint64_t target_ulong;

typedef union {
    uint8_t  ub[4];
    int8_t   sb[4];
    uint16_t uh[2];
    int16_t  sh[2];
    uint32_t uw[1];
    int32_t  sw[1];
} DSP32Value;

static inline int32_t mipsdsp_rshift1_add_q32(int32_t a, int32_t b)
{
    int64_t temp;

    temp = (int64_t)a + (int64_t)b;

    return (temp >> 1) & 0xFFFFFFFF;
}

#define MIPSDSP32_BINOP(name, func, element)                               \
target_ulong helper_##name(target_ulong rs, target_ulong rt)               \
{                                                                          \
    DSP32Value ds, dt;                                                     \
    unsigned int i;                                                        \
                                                                           \
    ds.sw[0] = rs;                                                         \
    dt.sw[0] = rt;                                                         \
                                                                           \
    for (i = 0; i < ARRAY_SIZE(ds.element); i++) {                         \
        ds.element[i] = mipsdsp_##func(ds.element[i], dt.element[i]);      \
    }                                                                      \
                                                                           \
    return (target_long)ds.sw[0];                                          \
}

MIPSDSP32_BINOP(addqh_w, rshift1_add_q32, sw)

