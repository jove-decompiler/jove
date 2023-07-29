#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

#define HELPER(name) glue(helper_, name)

static inline float32 float32_chs(float32 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) ^ 0x80000000);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

float32 VFP_HELPER(neg, s)(float32 a)
{
    return float32_chs(a);
}

