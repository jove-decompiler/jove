#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

#define float64_val(x) (x)

#define make_float64(x) (x)

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

void float_raise(uint8_t flags, float_status *status);

float64 float64_squash_input_denormal(float64 a, float_status *status);

int float64_is_signaling_nan(float64, float_status *status);

float64 float64_silence_nan(float64, float_status *status);

static inline int float64_is_infinity(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL ) == 0x7ff0000000000000LL;
}

static inline int float64_is_neg(float64 a)
{
    return float64_val(a) >> 63;
}

static inline int float64_is_zero(float64 a)
{
    return (float64_val(a) & 0x7fffffffffffffffLL) == 0;
}

static inline int float64_is_any_nan(float64 a)
{
    return ((float64_val(a) & ~(1ULL << 63)) > 0x7ff0000000000000ULL);
}

#define float64_zero make_float64(0)

#define float64_infinity make_float64(0x7ff0000000000000LL)

static inline float64 float64_set_sign(float64 a, int sign)
{
    return make_float64((float64_val(a) & 0x7fffffffffffffffULL)
                        | ((int64_t)sign << 63));
}

float64 float64_default_nan(float_status *status);

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

float64 HELPER(rsqrte_f64)(float64 input, void *fpstp)
{
    float_status *s = fpstp;
    float64 f64 = float64_squash_input_denormal(input, s);
    uint64_t val = float64_val(f64);
    bool f64_sign = float64_is_neg(f64);
    int f64_exp = extract64(val, 52, 11);
    uint64_t f64_frac = extract64(val, 0, 52);

    if (float64_is_any_nan(f64)) {
        float64 nan = f64;
        if (float64_is_signaling_nan(f64, s)) {
            float_raise(float_flag_invalid, s);
            nan = float64_silence_nan(f64, s);
        }
        if (s->default_nan_mode) {
            nan =  float64_default_nan(s);
        }
        return nan;
    } else if (float64_is_zero(f64)) {
        float_raise(float_flag_divbyzero, s);
        return float64_set_sign(float64_infinity, float64_is_neg(f64));
    } else if (float64_is_neg(f64)) {
        float_raise(float_flag_invalid, s);
        return float64_default_nan(s);
    } else if (float64_is_infinity(f64)) {
        return float64_zero;
    }

    f64_frac = recip_sqrt_estimate(&f64_exp, 3068, f64_frac);

    /* result = sign : result_exp<4:0> : estimate<7:0> : Zeros(44) */
    val = deposit64(0, 61, 1, f64_sign);
    val = deposit64(val, 52, 11, f64_exp);
    val = deposit64(val, 44, 8, extract64(f64_frac, 52 - 8, 8));
    return make_float64(val);
}

