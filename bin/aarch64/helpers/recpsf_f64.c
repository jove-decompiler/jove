#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#define float64_val(x) (x)

#define make_float64(x) (x)

typedef uint64_t float64;

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

float64 float64_squash_input_denormal(float64 a, float_status *status);

float64 float64_muladd(float64, float64, float64, int, float_status *status);

static inline float64 float64_chs(float64 a)
{
    /* Note that chs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) ^ 0x8000000000000000LL);
}

static inline bool float64_is_infinity(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL ) == 0x7ff0000000000000LL;
}

static inline bool float64_is_zero(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL) == 0;
}

#define float64_two make_float64(0x4000000000000000ULL)

float64 HELPER(recpsf_f64)(float64 a, float64 b, void *fpstp)
{
    float_status *fpst = fpstp;

    a = float64_squash_input_denormal(a, fpst);
    b = float64_squash_input_denormal(b, fpst);

    a = float64_chs(a);
    if ((float64_is_infinity(a) && float64_is_zero(b)) ||
        (float64_is_infinity(b) && float64_is_zero(a))) {
        return float64_two;
    }
    return float64_muladd(a, b, float64_two, 0, fpst);
}

