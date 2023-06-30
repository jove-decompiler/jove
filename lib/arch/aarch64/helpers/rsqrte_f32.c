#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

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

float32 float32_squash_input_denormal(float32 a, float_status *status);

bool float32_is_signaling_nan(float32, float_status *status);

float32 float32_silence_nan(float32, float_status *status);

static inline bool float32_is_infinity(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0x7f800000;
}

static inline bool float32_is_neg(float32 a)
{
    return float32_val(a) >> 31;
}

static inline bool float32_is_zero(float32 a)
{
    return (float32_val(a) & 0x7fffffff) == 0;
}

static inline bool float32_is_any_nan(float32 a)
{
    return ((float32_val(a) & ~(1 << 31)) > 0x7f800000UL);
}

static inline float32 float32_set_sign(float32 a, int sign)
{
    return make_float32((float32_val(a) & 0x7fffffff) | (sign << 31));
}

#define float32_zero make_float32(0)

#define float32_infinity make_float32(0x7f800000)

float32 float32_default_nan(float_status *status);

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

float32 HELPER(rsqrte_f32)(float32 input, void *fpstp)
{
    float_status *s = fpstp;
    float32 f32 = float32_squash_input_denormal(input, s);
    uint32_t val = float32_val(f32);
    uint32_t f32_sign = float32_is_neg(f32);
    int f32_exp = extract32(val, 23, 8);
    uint32_t f32_frac = extract32(val, 0, 23);
    uint64_t f64_frac;

    if (float32_is_any_nan(f32)) {
        float32 nan = f32;
        if (float32_is_signaling_nan(f32, s)) {
            float_raise(float_flag_invalid, s);
            if (!s->default_nan_mode) {
                nan = float32_silence_nan(f32, fpstp);
            }
        }
        if (s->default_nan_mode) {
            nan =  float32_default_nan(s);
        }
        return nan;
    } else if (float32_is_zero(f32)) {
        float_raise(float_flag_divbyzero, s);
        return float32_set_sign(float32_infinity, float32_is_neg(f32));
    } else if (float32_is_neg(f32)) {
        float_raise(float_flag_invalid, s);
        return float32_default_nan(s);
    } else if (float32_is_infinity(f32)) {
        return float32_zero;
    }

    /* Scale and normalize to a double-precision value between 0.25 and 1.0,
     * preserving the parity of the exponent.  */

    f64_frac = ((uint64_t) f32_frac) << 29;

    f64_frac = recip_sqrt_estimate(&f32_exp, 380, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(15) */
    val = deposit32(0, 31, 1, f32_sign);
    val = deposit32(val, 23, 8, f32_exp);
    val = deposit32(val, 15, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float32(val);
}

