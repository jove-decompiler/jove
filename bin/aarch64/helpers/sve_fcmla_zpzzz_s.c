#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

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

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

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

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define HELPER(name) glue(helper_, name)

float32 float32_muladd(float32, float32, float32, int, float_status *status);

static inline float32 float32_set_sign(float32 a, int sign)
{
    return make_float32((float32_val(a) & 0x7fffffff) | (sign << 31));
}

#define H1_2(x) (x)

void HELPER(sve_fcmla_zpzzz_s)(void *vd, void *vn, void *vm, void *va,
                               void *vg, void *status, uint32_t desc)
{
    intptr_t j, i = simd_oprsz(desc);
    unsigned rot = simd_data(desc);
    bool flip = rot & 1;
    float32 neg_imag, neg_real;
    uint64_t *g = vg;

    neg_imag = float32_set_sign(0, (rot & 2) != 0);
    neg_real = float32_set_sign(0, rot == 1 || rot == 2);

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            float32 e1, e2, e3, e4, nr, ni, mr, mi, d;

            /* I holds the real index; J holds the imag index.  */
            j = i - sizeof(float32);
            i -= 2 * sizeof(float32);

            nr = *(float32 *)(vn + H1_2(i));
            ni = *(float32 *)(vn + H1_2(j));
            mr = *(float32 *)(vm + H1_2(i));
            mi = *(float32 *)(vm + H1_2(j));

            e2 = (flip ? ni : nr);
            e1 = (flip ? mi : mr) ^ neg_real;
            e4 = e2;
            e3 = (flip ? mr : mi) ^ neg_imag;

            if (likely((pg >> (i & 63)) & 1)) {
                d = *(float32 *)(va + H1_2(i));
                d = float32_muladd(e2, e1, d, 0, status);
                *(float32 *)(vd + H1_2(i)) = d;
            }
            if (likely((pg >> (j & 63)) & 1)) {
                d = *(float32 *)(va + H1_2(j));
                d = float32_muladd(e4, e3, d, 0, status);
                *(float32 *)(vd + H1_2(j)) = d;
            }
        } while (i & 63);
    } while (i != 0);
}

