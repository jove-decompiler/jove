#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline int clrsb32(uint32_t val)
{
#if __has_builtin(__builtin_clrsb) || !defined(__clang__)
    return __builtin_clrsb(val);
#else
    return clz32(val ^ ((int32_t)val >> 1)) - 1;
#endif
}

#define HELPER(name) glue(helper_, name)

__attribute__((always_inline))
uint32_t HELPER(clrsb_i32)(uint32_t arg)
{
    return clrsb32(arg);
}

