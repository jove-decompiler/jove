#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

#define HELPER(name) glue(helper_, name)

__attribute__((always_inline))
uint32_t HELPER(ctz_i32)(uint32_t arg, uint32_t zero_val)
{
    return arg ? ctz32(arg) : zero_val;
}

