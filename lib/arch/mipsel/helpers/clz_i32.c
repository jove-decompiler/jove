#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int clz8(uint8_t val)
{
    return val ? __builtin_clz(val) - 24 : 8;
}

static inline int clz32(uint32_t val)
{
    return val ? __builtin_clz(val) : 32;
}

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(clz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? clz32(arg) : zero_val;
}

