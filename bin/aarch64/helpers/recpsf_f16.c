#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

typedef uint16_t float16;

#define float16_val(x) (x)

#define make_float16(x) (x)

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

float16 float16_squash_input_denormal(float16 a, float_status *status);

float16 float16_muladd(float16, float16, float16, int, float_status *status);

static inline bool float16_is_infinity(float16 a)
{
    return (float16_val(a) & 0x7fff) == 0x7c00;
}

static inline bool float16_is_zero(float16 a)
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

#define float16_two make_float16(0x4000)

uint32_t HELPER(recpsf_f16)(uint32_t a, uint32_t b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float16_squash_input_denormal(a, fpst);
    b = float16_squash_input_denormal(b, fpst);

    a = float16_chs(a);
    if ((float16_is_infinity(a) && float16_is_zero(b)) ||
        (float16_is_infinity(b) && float16_is_zero(a))) {
        return float16_two;
    }
    return float16_muladd(a, b, float16_two, 0, fpst);
}

