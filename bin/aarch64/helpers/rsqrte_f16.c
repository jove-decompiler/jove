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

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
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

static inline bool float16_is_neg(float16 a)
{
    return float16_val(a) >> 15;
}

static inline bool float16_is_infinity(float16 a)
{
    return (float16_val(a) & 0x7fff) == 0x7c00;
}

static inline bool float16_is_zero(float16 a)
{
    return (float16_val(a) & 0x7fff) == 0;
}

static inline float16 float16_set_sign(float16 a, int sign)
{
    return make_float16((float16_val(a) & 0x7fff) | (sign << 15));
}

#define float16_zero make_float16(0)

#define float16_infinity make_float16(0x7c00)

float16 float16_default_nan(float_status *status);

static int do_recip_sqrt_estimate(int a)
{
    int b, estimate;

    assert(128 <= a && a < 512);
    if (a < 256) {
        a = a * 2 + 1;
    } else {
        a = (a >> 1) << 1;
        a = (a + 1) * 2;
    }
    b = 512;
    while (a * (b + 1) * (b + 1) < (1 << 28)) {
        b += 1;
    }
    estimate = (b + 1) / 2;
    assert(256 <= estimate && estimate < 512);

    return estimate;
}

static uint64_t recip_sqrt_estimate(int *exp , int exp_off, uint64_t frac)
{
    int estimate;
    uint32_t scaled;

    if (*exp == 0) {
        while (extract64(frac, 51, 1) == 0) {
            frac = frac << 1;
            *exp -= 1;
        }
        frac = extract64(frac, 0, 51) << 1;
    }

    if (*exp & 1) {
        /* scaled = UInt('01':fraction<51:45>) */
        scaled = deposit32(1 << 7, 0, 7, extract64(frac, 45, 7));
    } else {
        /* scaled = UInt('1':fraction<51:44>) */
        scaled = deposit32(1 << 8, 0, 8, extract64(frac, 44, 8));
    }
    estimate = do_recip_sqrt_estimate(scaled);

    *exp = (exp_off - *exp) / 2;
    return extract64(estimate, 0, 8) << 44;
}

uint32_t HELPER(rsqrte_f16)(uint32_t input, void *fpstp)
{
    float_status *s = fpstp;
    float16 f16 = float16_squash_input_denormal(input, s);
    uint16_t val = float16_val(f16);
    bool f16_sign = float16_is_neg(f16);
    int f16_exp = extract32(val, 10, 5);
    uint16_t f16_frac = extract32(val, 0, 10);
    uint64_t f64_frac;

    if (float16_is_any_nan(f16)) {
        float16 nan = f16;
        if (float16_is_signaling_nan(f16, s)) {
            float_raise(float_flag_invalid, s);
            if (!s->default_nan_mode) {
                nan = float16_silence_nan(f16, fpstp);
            }
        }
        if (s->default_nan_mode) {
            nan =  float16_default_nan(s);
        }
        return nan;
    } else if (float16_is_zero(f16)) {
        float_raise(float_flag_divbyzero, s);
        return float16_set_sign(float16_infinity, f16_sign);
    } else if (f16_sign) {
        float_raise(float_flag_invalid, s);
        return float16_default_nan(s);
    } else if (float16_is_infinity(f16)) {
        return float16_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f16_frac) << (52 - 10);

    f64_frac = recip_sqrt_estimate(&f16_exp, 44, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(2) */
    val = deposit32(0, 15, 1, f16_sign);
    val = deposit32(val, 10, 5, f16_exp);
    val = deposit32(val, 2, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float16(val);
}

