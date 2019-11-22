#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

#define make_float16(x) (x)

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
    /* not always used -- see snan_bit_is_one() in softfloat-specialize.h */
    flag snan_bit_is_one;
} float_status;

#define HELPER(name) glue(helper_, name)

float16 float16_squash_input_denormal(float16 a, float_status *status);

enum {
    float_muladd_negate_c = 1,
    float_muladd_negate_product = 2,
    float_muladd_negate_result = 4,
    float_muladd_halve_result = 8,
};

float16 float16_muladd(float16, float16, float16, int, float_status *status);

static inline int float16_is_infinity(float16 a)
{
    return (float16_val(a) & 0x7fff) == 0x7c00;
}

static inline int float16_is_zero(float16 a)
{
    return (float16_val(a) & 0x7fff) == 0;
}

static inline float16 float16_chs(float16 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float16(float16_val(a) ^ 0x8000);
}

#define float16_three make_float16(0x4200)

#define float16_one_point_five make_float16(0x3e00)

uint32_t HELPER(rsqrtsf_f16)(uint32_t a, uint32_t b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float16_squash_input_denormal(a, fpst);
    b = float16_squash_input_denormal(b, fpst);

    a = float16_chs(a);
    if ((float16_is_infinity(a) && float16_is_zero(b)) ||
        (float16_is_infinity(b) && float16_is_zero(a))) {
        return float16_one_point_five;
    }
    return float16_muladd(a, b, float16_three, float_muladd_halve_result, fpst);
}

