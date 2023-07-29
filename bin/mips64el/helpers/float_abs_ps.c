#include <stdint.h>

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

static inline float32 float32_abs(float32 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) & 0x7fffffff);
}

uint64_t helper_float_abs_ps(uint64_t fdt0)
{
    uint32_t wt0;
    uint32_t wth0;

    wt0 = float32_abs(fdt0 & 0XFFFFFFFF);
    wth0 = float32_abs(fdt0 >> 32);
    return ((uint64_t)wth0 << 32) | wt0;
}

