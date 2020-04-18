#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

#define HELPER(name) glue(helper_, name)

__attribute__((always_inline))
uint64_t HELPER(clz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? clz64(arg) : zero_val;
}

