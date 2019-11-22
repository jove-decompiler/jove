#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

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

float64 HELPER(frint32_d)(float64 f, void *fpst)
{
    return frint_d(f, fpst, 32);
}

