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

#define HELPER(name) glue(helper_, name)

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

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

float16 float16_muladd(float16, float16, float16, int, float_status *status);

#define H2(x)   (x)

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_fcmlah)(void *vd, void *vn, void *vm, void *va,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float16 *d = vd, *n = vn, *m = vm, *a = va;
    float_status *fpst = vfpst;
    intptr_t flip = extract32(desc, SIMD_DATA_SHIFT, 1);
    uint32_t neg_imag = extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint32_t neg_real = flip ^ neg_imag;
    uintptr_t i;

    /* Shift boolean to the sign bit so we can xor to negate.  */
    neg_real <<= 15;
    neg_imag <<= 15;

    for (i = 0; i < opr_sz / 2; i += 2) {
        float16 e2 = n[H2(i + flip)];
        float16 e1 = m[H2(i + flip)] ^ neg_real;
        float16 e4 = e2;
        float16 e3 = m[H2(i + 1 - flip)] ^ neg_imag;

        d[H2(i)] = float16_muladd(e2, e1, a[H2(i)], 0, fpst);
        d[H2(i + 1)] = float16_muladd(e4, e3, a[H2(i + 1)], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

