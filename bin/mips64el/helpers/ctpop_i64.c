#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int ctpop64(uint64_t val)
{
    return __builtin_popcountll(val);
}

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(ctpop_i64)(uint64_t arg)
{
    return ctpop64(arg);
}

