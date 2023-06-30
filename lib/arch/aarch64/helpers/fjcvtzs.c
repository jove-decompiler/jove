#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

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

enum {
    float_flag_invalid         = 0x0001,
    float_flag_divbyzero       = 0x0002,
    float_flag_overflow        = 0x0004,
    float_flag_underflow       = 0x0008,
    float_flag_inexact         = 0x0010,
    float_flag_input_denormal  = 0x0020,
    float_flag_output_denormal = 0x0040,
    float_flag_invalid_isi     = 0x0080,  /* inf - inf */
    float_flag_invalid_imz     = 0x0100,  /* inf * 0 */
    float_flag_invalid_idi     = 0x0200,  /* inf / inf */
    float_flag_invalid_zdz     = 0x0400,  /* 0 / 0 */
    float_flag_invalid_sqrt    = 0x0800,  /* sqrt(-x) */
    float_flag_invalid_cvti    = 0x1000,  /* non-nan to integer */
    float_flag_invalid_snan    = 0x2000,  /* any operand was snan */
};

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

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

static inline uint64_t deposit64(uint64_t value, int start, int length,
                                 uint64_t fieldval)
{
    uint64_t mask;
    assert(start >= 0 && length > 0 && length <= 64 - start);
    mask = (~0ULL >> (64 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

#define HELPER(name) glue(helper_, name)

static inline void float_raise(uint16_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

uint64_t HELPER(fjcvtzs)(float64 value, void *vstatus)
{
    float_status *status = vstatus;
    uint32_t exp, sign;
    uint64_t frac;
    uint32_t inexact = 1; /* !Z */

    sign = extract64(value, 63, 1);
    exp = extract64(value, 52, 11);
    frac = extract64(value, 0, 52);

    if (exp == 0) {
        /* While not inexact for IEEE FP, -0.0 is inexact for JavaScript.  */
        inexact = sign;
        if (frac != 0) {
            if (status->flush_inputs_to_zero) {
                float_raise(float_flag_input_denormal, status);
            } else {
                float_raise(float_flag_inexact, status);
                inexact = 1;
            }
        }
        frac = 0;
    } else if (exp == 0x7ff) {
        /* This operation raises Invalid for both NaN and overflow (Inf).  */
        float_raise(float_flag_invalid, status);
        frac = 0;
    } else {
        int true_exp = exp - 1023;
        int shift = true_exp - 52;

        /* Restore implicit bit.  */
        frac |= 1ull << 52;

        /* Shift the fraction into place.  */
        if (shift >= 0) {
            /* The number is so large we must shift the fraction left.  */
            if (shift >= 64) {
                /* The fraction is shifted out entirely.  */
                frac = 0;
            } else {
                frac <<= shift;
            }
        } else if (shift > -64) {
            /* Normal case -- shift right and notice if bits shift out.  */
            inexact = (frac << (64 + shift)) != 0;
            frac >>= -shift;
        } else {
            /* The fraction is shifted out entirely.  */
            frac = 0;
        }

        /* Notice overflow or inexact exceptions.  */
        if (true_exp > 31 || frac > (sign ? 0x80000000ull : 0x7fffffff)) {
            /* Overflow, for which this operation raises invalid.  */
            float_raise(float_flag_invalid, status);
            inexact = 1;
        } else if (inexact) {
            float_raise(float_flag_inexact, status);
        }

        /* Honor the sign.  */
        if (sign) {
            frac = -frac;
        }
    }

    /* Pack the result and the env->ZF representation of Z together.  */
    return deposit64(frac, 32, 32, inexact);
}

