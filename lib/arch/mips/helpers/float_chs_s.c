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

uint32_t helper_float_chs_s(uint32_t fst0)
{
    return float32_chs(fst0);
}

