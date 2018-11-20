#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

typedef uint8_t flag;

#define float64_val(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

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

int float64_lt(float64, float64, float_status *status);

static inline float64 float64_abs(float64 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) & 0x7fffffffffffffffLL);
}

uint64_t HELPER(neon_acgt_f64)(uint64_t a, uint64_t b, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f0 = float64_abs(make_float64(a));
    float64 f1 = float64_abs(make_float64(b));
    return -float64_lt(f1, f0, fpst);
}

