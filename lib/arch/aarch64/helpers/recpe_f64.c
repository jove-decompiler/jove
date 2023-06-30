#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

#define G_STRFUNC     ((const char*) (__func__))

#define G_STMT_START  do

#define G_STMT_END    while (0)

# define G_NORETURN __attribute__ ((__noreturn__))

#define _GLIB_EXTERN extern

#define GLIB_AVAILABLE_IN_ALL                   _GLIB_EXTERN

typedef char   gchar;

#define G_LOG_DOMAIN    ((gchar*) 0)

#define g_assert_not_reached()          G_STMT_START { g_assertion_message_expr (G_LOG_DOMAIN, __FILE__, __LINE__, G_STRFUNC, NULL); } G_STMT_END

GLIB_AVAILABLE_IN_ALL
G_NORETURN
void    g_assertion_message_expr        (const char     *domain,
                                         const char     *file,
                                         int             line,
                                         const char     *func,
                                         const char     *expr);

#include <stddef.h>

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

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
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

float64 float64_squash_input_denormal(float64 a, float_status *status);

bool float64_is_signaling_nan(float64, float_status *status);

float64 float64_silence_nan(float64, float_status *status);

static inline bool float64_is_infinity(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL ) == 0x7ff0000000000000LL;
}

static inline bool float64_is_neg(float64 a)
{
    return float64_val(a) >> 63;
}

static inline bool float64_is_zero(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL) == 0;
}

static inline bool float64_is_any_nan(float64 a)
{
    return ((float64_val(a) & ~(1ULL << 63)) > 0x7ff0000000000000ULL);
}

static inline float64 float64_set_sign(float64 a, int sign)
{
    return make_float64((float64_val(a) & 0x7fffffffffffffffULL)
                        | ((int64_t)sign << 63));
}

#define float64_zero make_float64(0)

#define float64_infinity make_float64(0x7ff0000000000000LL)

float64 float64_default_nan(float_status *status);

#define float64_maxnorm make_float64(0x7fefffffffffffffLL)

static int recip_estimate(int input)
{
    int a, b, r;
    assert(256 <= input && input < 512);
    a = (input * 2) + 1;
    b = (1 << 19) / a;
    r = (b + 1) >> 1;
    assert(256 <= r && r < 512);
    return r;
}

static uint64_t call_recip_estimate(int *exp, int exp_off, uint64_t frac)
{
    uint32_t scaled, estimate;
    uint64_t result_frac;
    int result_exp;

    /* Handle sub-normals */
    if (*exp == 0) {
        if (extract64(frac, 51, 1) == 0) {
            *exp = -1;
            frac <<= 2;
        } else {
            frac <<= 1;
        }
    }

    /* scaled = UInt('1':fraction<51:44>) */
    scaled = deposit32(1 << 8, 0, 8, extract64(frac, 44, 8));
    estimate = recip_estimate(scaled);

    result_exp = exp_off - *exp;
    result_frac = deposit64(0, 44, 8, estimate);
    if (result_exp == 0) {
        result_frac = deposit64(result_frac >> 1, 51, 1, 1);
    } else if (result_exp == -1) {
        result_frac = deposit64(result_frac >> 2, 50, 2, 1);
        result_exp = 0;
    }

    *exp = result_exp;

    return result_frac;
}

static bool round_to_inf(float_status *fpst, bool sign_bit)
{
    switch (fpst->float_rounding_mode) {
    case float_round_nearest_even: /* Round to Nearest */
        return true;
    case float_round_up: /* Round to +Inf */
        return !sign_bit;
    case float_round_down: /* Round to -Inf */
        return sign_bit;
    case float_round_to_zero: /* Round to Zero */
        return false;
    default:
        g_assert_not_reached();
    }
}

float64 HELPER(recpe_f64)(float64 input, void *fpstp)
{
    float_status *fpst = fpstp;
    float64 f64 = float64_squash_input_denormal(input, fpst);
    uint64_t f64_val = float64_val(f64);
    bool f64_sign = float64_is_neg(f64);
    int f64_exp = extract64(f64_val, 52, 11);
    uint64_t f64_frac = extract64(f64_val, 0, 52);

    /* Deal with any special cases */
    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, fpst)) {
            float_raise(float_flag_invalid, fpst);
            if (!fpst->default_nan_mode) {
                nan = float64_silence_nan(f64, fpst);
            }
        }
        if (fpst->default_nan_mode) {
            nan =  float64_default_nan(fpst);
        }
        return nan;
    } else if (float64_is_infinity(f64)) {
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, fpst);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if ((f64_val & ~(1ULL << 63)) < (1ULL << 50)) {
        /* Abs(value) < 2.0^-1024 */
        float_raise(float_flag_overflow | float_flag_inexact, fpst);
        if (round_to_inf(fpst, f64_sign)) {
            return float64_set_sign(float64_infinity, f64_sign);
        } else {
            return float64_set_sign(float64_maxnorm, f64_sign);
        }
    } else if (f64_exp >= 2045 && fpst->flush_to_zero) {
        float_raise(float_flag_underflow, fpst);
        return float64_set_sign(float64_zero, float64_is_neg(f64));
    }

    f64_frac = call_recip_estimate(&f64_exp, 2045, f64_frac);

    /* result = sign : result_exp<10:0> : fraction<51:0>; */
    f64_val = deposit64(0, 63, 1, f64_sign);
    f64_val = deposit64(f64_val, 52, 11, f64_exp);
    f64_val = deposit64(f64_val, 0, 52, f64_frac);
    return make_float64(f64_val);
}

