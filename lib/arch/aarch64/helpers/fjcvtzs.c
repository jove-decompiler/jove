#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint64_t float64;

enum {
    float_flag_invalid   =  1,
    float_flag_divbyzero =  4,
    float_flag_overflow  =  8,
    float_flag_underflow = 16,
    float_flag_inexact   = 32,
    float_flag_input_denormal = 64,
    float_flag_output_denormal = 128
};

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

void float_raise(uint8_t flags, float_status *status);

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

