#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

typedef uint16_t float16;

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

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

#define HELPER(name) glue(helper_, name)

float16 float16_maxnum(float16, float16, float_status *status);

#define ADVSIMD_HELPER(name, suffix) HELPER(glue(glue(advsimd_, name), suffix))

#define ADVSIMD_TWOHALFOP(name)                                         \
uint32_t ADVSIMD_HELPER(name, 2h)(uint32_t two_a, uint32_t two_b, void *fpstp) \
{ \
    float16  a1, a2, b1, b2;                        \
    uint32_t r1, r2;                                \
    float_status *fpst = fpstp;                     \
    a1 = extract32(two_a, 0, 16);                   \
    a2 = extract32(two_a, 16, 16);                  \
    b1 = extract32(two_b, 0, 16);                   \
    b2 = extract32(two_b, 16, 16);                  \
    r1 = float16_ ## name(a1, b1, fpst);            \
    r2 = float16_ ## name(a2, b2, fpst);            \
    return deposit32(r1, 16, 16, r2);               \
}

ADVSIMD_TWOHALFOP(maxnum)

