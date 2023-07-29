#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

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

#define HELPER(name) glue(helper_, name)

static inline void set_float_exception_flags(int val, float_status *status)
{
    status->float_exception_flags = val;
}

static inline int get_float_exception_flags(float_status *status)
{
    return status->float_exception_flags;
}

float64 float64_round_to_int(float64, float_status *status);

static float64 frint_d(float64 f, float_status *fpst, int intsize)
{
    int old_flags = get_float_exception_flags(fpst);
    uint32_t exp = extract64(f, 52, 11);

    if (unlikely(exp == 0x7ff)) {
        /* NaN or Inf.  */
        goto overflow;
    }

    /* Round and re-extract the exponent.  */
    f = float64_round_to_int(f, fpst);
    exp = extract64(f, 52, 11);

    /* Validate the range of the result.  */
    if (exp < 1022 + intsize) {
        /* abs(F) <= INT{N}_MAX */
        return f;
    }
    if (exp == 1022 + intsize) {
        uint64_t sign = extract64(f, 63, 1);
        uint64_t frac = extract64(f, 0, 52);
        if (sign && frac == 0) {
            /* F == INT{N}_MIN */
            return f;
        }
    }

 overflow:
    /*
     * Raise Invalid and return INT{N}_MIN as a float.  Revert any
     * inexact exception float64_round_to_int may have raised.
     */
    set_float_exception_flags(old_flags | float_flag_invalid, fpst);
    return (uint64_t)(0x800 + 1022 + intsize) << 52;
}

float64 HELPER(frint64_d)(float64 f, void *fpst)
{
    return frint_d(f, fpst, 64);
}

