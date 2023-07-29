#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint16_t float16;

#define float16_val(x) (x)

#define make_float16(x) (x)

#define HELPER(name) glue(helper_, name)

#define dh_ctype_f16 uint32_t

static inline float16 float16_abs(float16 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float16(float16_val(a) & 0x7fff);
}

#define VFP_HELPER(name, p) HELPER(glue(glue(vfp_,name),p))

dh_ctype_f16 VFP_HELPER(abs, h)(dh_ctype_f16 a)
{
    return float16_abs(a);
}

