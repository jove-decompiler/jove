#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int clrsb64(uint64_t val)
{
#if __has_builtin(__builtin_clrsbll) || !defined(__clang__)
    return __builtin_clrsbll(val);
#else
    return clz64(val ^ ((int64_t)val >> 1)) - 1;
#endif
}

#define HELPER(name) glue(helper_, name)

__attribute__((always_inline))
uint64_t HELPER(clrsb_i64)(uint64_t arg)
{
    return clrsb64(arg);
}

