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

uint32_t helper_float_abs_s(uint32_t fst0)
{
    return float32_abs(fst0);
}

