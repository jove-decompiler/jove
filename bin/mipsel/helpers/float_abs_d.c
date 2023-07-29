#include <stdint.h>

#define float64_val(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

static inline float64 float64_abs(float64 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) & 0x7fffffffffffffffLL);
}

uint64_t helper_float_abs_d(uint64_t fdt0)
{
   return float64_abs(fdt0);
}

