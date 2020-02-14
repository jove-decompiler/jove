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

typedef uint64_t target_ulong;

typedef union {
    uint8_t  ub[8];
    int8_t   sb[8];
    uint16_t uh[4];
    int16_t  sh[4];
    uint32_t uw[2];
    int32_t  sw[2];
    uint64_t ul[1];
    int64_t  sl[1];
} DSP64Value;

static inline uint8_t mipsdsp_rshift1_add_u8(uint8_t a, uint8_t b)
{
    uint16_t temp;

    temp = (uint16_t)a + (uint16_t)b;

    return (temp >> 1) & 0x00FF;
}

#define MIPSDSP64_BINOP(name, func, element)                               \
target_ulong helper_##name(target_ulong rs, target_ulong rt)               \
{                                                                          \
    DSP64Value ds, dt;                                                     \
    unsigned int i;                                                        \
                                                                           \
    ds.sl[0] = rs;                                                         \
    dt.sl[0] = rt;                                                         \
                                                                           \
    for (i = 0 ; i < ARRAY_SIZE(ds.element); i++) {                        \
        ds.element[i] = mipsdsp_##func(ds.element[i], dt.element[i]);      \
    }                                                                      \
                                                                           \
    return ds.sl[0];                                                       \
}

MIPSDSP64_BINOP(adduh_ob, rshift1_add_u8, ub)

