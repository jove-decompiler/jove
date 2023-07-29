#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int ctpop8(uint8_t val)
{
    return __builtin_popcount(val);
}

static inline int ctpop32(uint32_t val)
{
    return __builtin_popcount(val);
}

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(ctpop_i32)(uint32_t arg)
{
    return ctpop32(arg);
}

