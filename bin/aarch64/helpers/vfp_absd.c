#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define float64_val(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

#define HELPER(name) glue(helper_, name)

static inline float64 float64_abs(float64 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) & 0x7fffffffffffffffLL);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

float64 VFP_HELPER(abs, d)(float64 a)
{
    return float64_abs(a);
}

