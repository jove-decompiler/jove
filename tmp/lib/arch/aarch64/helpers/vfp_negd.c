#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define float64_val(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

#define HELPER(name) glue(helper_, name)

static inline float64 float64_chs(float64 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) ^ 0x8000000000000000LL);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

float64 VFP_HELPER(neg, d)(float64 a)
{
    return float64_chs(a);
}

