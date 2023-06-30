#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

typedef uint16_t float16;

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

static inline void set_flush_to_zero(bool val, float_status *status)
{
    status->flush_to_zero = val;
}

static inline bool get_flush_to_zero(float_status *status)
{
    return status->flush_to_zero;
}

float16 float64_to_float16(float64 a, bool ieee, float_status *status);

uint32_t HELPER(vfp_fcvt_f64_to_f16)(float64 a, void *fpstp, uint32_t ahp_mode)
{
    /* Squash FZ16 to 0 for the duration of conversion.  In this case,
     * it would affect flushing output denormals.
     */
    float_status *fpst = fpstp;
    bool save = get_flush_to_zero(fpst);
    set_flush_to_zero(false, fpst);
    float16 r = float64_to_float16(a, !ahp_mode, fpst);
    set_flush_to_zero(save, fpst);
    return r;
}

