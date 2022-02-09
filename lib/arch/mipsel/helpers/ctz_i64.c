#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

#define HELPER(name) glue(helper_, name)

__attribute__((always_inline))
uint64_t HELPER(ctz_i64)(uint64_t arg, uint64_t zero_val)
{
    return arg ? ctz64(arg) : zero_val;
}

