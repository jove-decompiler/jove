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

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) * 8 + 8;
}

static inline intptr_t simd_oprsz(uint32_t desc)
{
    uint32_t f = extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS);
    intptr_t o = f * 8 + 8;
    intptr_t m = simd_maxsz(desc);
    return f == 2 ? m : o;
}

#define HELPER(name) glue(helper_, name)

float64 float64_add(float64, float64, float_status *status);

float64 float64_mul(float64, float64, float_status *status);

void HELPER(fmmla_d)(void *vd, void *vn, void *vm, void *va,
                     void *status, uint32_t desc)
{
    intptr_t s, opr_sz = simd_oprsz(desc) / (sizeof(float64) * 4);

    for (s = 0; s < opr_sz; ++s) {
        float64 *n = vn + s * sizeof(float64) * 4;
        float64 *m = vm + s * sizeof(float64) * 4;
        float64 *a = va + s * sizeof(float64) * 4;
        float64 *d = vd + s * sizeof(float64) * 4;
        float64 n00 = n[0], n01 = n[1], n10 = n[2], n11 = n[3];
        float64 m00 = m[0], m01 = m[1], m10 = m[2], m11 = m[3];
        float64 p0, p1;

        /* i = 0, j = 0 */
        p0 = float64_mul(n00, m00, status);
        p1 = float64_mul(n01, m01, status);
        d[0] = float64_add(a[0], float64_add(p0, p1, status), status);

        /* i = 0, j = 1 */
        p0 = float64_mul(n00, m10, status);
        p1 = float64_mul(n01, m11, status);
        d[1] = float64_add(a[1], float64_add(p0, p1, status), status);

        /* i = 1, j = 0 */
        p0 = float64_mul(n10, m00, status);
        p1 = float64_mul(n11, m01, status);
        d[2] = float64_add(a[2], float64_add(p0, p1, status), status);

        /* i = 1, j = 1 */
        p0 = float64_mul(n10, m10, status);
        p1 = float64_mul(n11, m11, status);
        d[3] = float64_add(a[3], float64_add(p0, p1, status), status);
    }
}

