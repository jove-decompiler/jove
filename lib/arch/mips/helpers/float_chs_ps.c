#include <stdint.h>

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

static inline float32 float32_chs(float32 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) ^ 0x80000000);
}

uint64_t helper_float_chs_ps(uint64_t fdt0)
{
    uint32_t wt0;
    uint32_t wth0;

    wt0 = float32_chs(fdt0 & 0XFFFFFFFF);
    wth0 = float32_chs(fdt0 >> 32);
    return ((uint64_t)wth0 << 32) | wt0;
}

