#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

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

static inline void float_raise(uint16_t flags, float_status *status)
{
    status->float_exception_flags |= flags;
}

float16 float16_squash_input_denormal(float16 a, float_status *status);

bool float16_is_signaling_nan(float16, float_status *status);

float16 float16_silence_nan(float16, float_status *status);

static inline bool float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

float16 float16_default_nan(float_status *status);

uint32_t HELPER(frecpx_f16)(uint32_t a, void *fpstp)
{
    float_status *fpst = fpstp;
    uint16_t val16, sbit;
    int16_t exp;

    if (float16_is_any_nan(a)) {
        float16 nan = a;
        if (float16_is_signaling_nan(a, fpst)) {
            float_raise(float_flag_invalid, fpst);
            if (!fpst->default_nan_mode) {
                nan = float16_silence_nan(a, fpst);
            }
        }
        if (fpst->default_nan_mode) {
            nan = float16_default_nan(fpst);
        }
        return nan;
    }

    a = float16_squash_input_denormal(a, fpst);

    val16 = float16_val(a);
    sbit = 0x8000 & val16;
    exp = extract32(val16, 10, 5);

    if (exp == 0) {
        return make_float16(deposit32(sbit, 10, 5, 0x1e));
    } else {
        return make_float16(deposit32(sbit, 10, 5, ~exp));
    }
}

