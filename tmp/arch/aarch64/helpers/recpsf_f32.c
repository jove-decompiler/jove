#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint8_t flag;

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

typedef struct float_status {
    signed char float_detect_tininess;
    signed char float_rounding_mode;
    uint8_t     float_exception_flags;
    signed char floatx80_rounding_precision;
    /* should denormalised results go to zero and set the inexact flag? */
    flag flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    flag flush_inputs_to_zero;
    flag default_nan_mode;
    flag snan_bit_is_one;
} float_status;

#define HELPER(name) glue(helper_, name)

float32 float32_squash_input_denormal(float32 a, float_status *status);

float32 float32_muladd(float32, float32, float32, int, float_status *status);

static inline float32 float32_chs(float32 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) ^ 0x80000000);
}

static inline int float32_is_infinity(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0x7f800000;
}

static inline int float32_is_zero(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0;
}

#define float32_two make_float32(0x40000000)

float32 HELPER(recpsf_f32)(float32 a, float32 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float32_squash_input_denormal(a, fpst);
    b = float32_squash_input_denormal(b, fpst);

    a = float32_chs(a);
    if ((float32_is_infinity(a) && float32_is_zero(b)) ||
        (float32_is_infinity(b) && float32_is_zero(a))) {
        return float32_two;
    }
    return float32_muladd(a, b, float32_two, 0, fpst);
}

