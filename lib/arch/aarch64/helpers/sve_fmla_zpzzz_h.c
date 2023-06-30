#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

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

float16 float16_muladd(float16, float16, float16, int, float_status *status);

#define H1_2(x) (x)

static void do_fmla_zpzzz_h(void *vd, void *vn, void *vm, void *va, void *vg,
                            float_status *status, uint32_t desc,
                            uint16_t neg1, uint16_t neg3)
{
    intptr_t i = simd_oprsz(desc);
    uint64_t *g = vg;

    do {
        uint64_t pg = g[(i - 1) >> 6];
        do {
            i -= 2;
            if (likely((pg >> (i & 63)) & 1)) {
                float16 e1, e2, e3, r;

                e1 = *(uint16_t *)(vn + H1_2(i)) ^ neg1;
                e2 = *(uint16_t *)(vm + H1_2(i));
                e3 = *(uint16_t *)(va + H1_2(i)) ^ neg3;
                r = float16_muladd(e1, e2, e3, 0, status);
                *(uint16_t *)(vd + H1_2(i)) = r;
            }
        } while (i & 63);
    } while (i != 0);
}

void HELPER(sve_fmla_zpzzz_h)(void *vd, void *vn, void *vm, void *va,
                              void *vg, void *status, uint32_t desc)
{
    do_fmla_zpzzz_h(vd, vn, vm, va, vg, status, desc, 0, 0);
}

