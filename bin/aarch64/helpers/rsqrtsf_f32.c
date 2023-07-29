#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

typedef enum __attribute__((__packed__)) {
    float_round_nearest_even = 0,
    float_round_down         = 1,
    float_round_up           = 2,
    float_round_to_zero      = 3,
    float_round_ties_away    = 4,
    /* Not an IEEE rounding mode: round to closest odd, overflow to max */
    float_round_to_odd       = 5,
    /* Not an IEEE rounding mode: round to closest odd, overflow to inf */
    float_round_to_odd_inf   = 6,
} FloatRoundMode;

typedef enum __attribute__((__packed__)) {
    floatx80_precision_x,
    floatx80_precision_d,
    floatx80_precision_s,
} FloatX80RoundPrec;

typedef struct float_status {
    uint16_t float_exception_flags;
    FloatRoundMode float_rounding_mode;
    FloatX80RoundPrec floatx80_rounding_precision;
    bool tininess_before_rounding;
    /* should denormalised results go to zero and set the inexact flag? */
    bool flush_to_zero;
    /* should denormalised inputs go to zero and set the input_denormal flag? */
    bool flush_inputs_to_zero;
    bool default_nan_mode;
    /*
     * The flags below are not used on all specializations and may
     * constant fold away (see snan_bit_is_one()/no_signalling_nans() in
     * softfloat-specialize.inc.c)
     */
    bool snan_bit_is_one;
    bool use_first_nan;
    bool no_signaling_nans;
    /* should overflowed results subtract re_bias to its exponent? */
    bool rebias_overflow;
    /* should underflowed results add re_bias to its exponent? */
    bool rebias_underflow;
} float_status;

#define HELPER(name) glue(helper_, name)

float32 float32_squash_input_denormal(float32 a, float_status *status);

enum {
    float_muladd_negate_c = 1,
    float_muladd_negate_product = 2,
    float_muladd_negate_result = 4,
    float_muladd_halve_result = 8,
};

float32 float32_muladd(float32, float32, float32, int, float_status *status);

static inline float32 float32_chs(float32 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) ^ 0x80000000);
}

static inline bool float32_is_infinity(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0x7f800000;
}

static inline bool float32_is_zero(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0;
}

#define float32_one_point_five make_float32(0x3fc00000)

#define float32_three make_float32(0x40400000)

float32 HELPER(rsqrtsf_f32)(float32 a, float32 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float32_squash_input_denormal(a, fpst);
    b = float32_squash_input_denormal(b, fpst);

    a = float32_chs(a);
    if ((float32_is_infinity(a) && float32_is_zero(b)) ||
        (float32_is_infinity(b) && float32_is_zero(a))) {
        return float32_one_point_five;
    }
    return float32_muladd(a, b, float32_three, float_muladd_halve_result, fpst);
}

