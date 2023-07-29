#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef uint16_t float16;

typedef uint32_t float32;

#define float16_val(x) (x)

#define float32_val(x) (x)

#define float64_val(x) (x)

#define make_float16(x) (x)

#define make_float32(x) (x)

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

typedef enum {
    float_relation_less      = -1,
    float_relation_equal     =  0,
    float_relation_greater   =  1,
    float_relation_unordered =  2
} FloatRelation;

FloatRelation float16_compare(float16, float16, float_status *status);

static inline float16 float16_abs(float16 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float16(float16_val(a) & 0x7fff);
}

FloatRelation float32_compare(float32, float32, float_status *status);

static inline float32 float32_abs(float32 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) & 0x7fffffff);
}

FloatRelation float64_compare(float64, float64, float_status *status);

static inline float64 float64_abs(float64 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) & 0x7fffffffffffffffLL);
}

#define H1_2(x) (x)

#define H1_4(x) (x)

#define H1_8(x) (x)

#define DO_FPCMP_PPZZ(NAME, TYPE, H, OP)                                \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg,               \
                  void *status, uint32_t desc)                          \
{                                                                       \
    intptr_t i = simd_oprsz(desc), j = (i - 1) >> 6;                    \
    uint64_t *d = vd, *g = vg;                                          \
    do {                                                                \
        uint64_t out = 0, pg = g[j];                                    \
        do {                                                            \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);                    \
            if (likely((pg >> (i & 63)) & 1)) {                         \
                TYPE nn = *(TYPE *)(vn + H(i));                         \
                TYPE mm = *(TYPE *)(vm + H(i));                         \
                out |= OP(TYPE, nn, mm, status);                        \
            }                                                           \
        } while (i & 63);                                               \
        d[j--] = out;                                                   \
    } while (i > 0);                                                    \
}

#define DO_FPCMP_PPZZ_H(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_h, float16, H1_2, OP)

#define DO_FPCMP_PPZZ_S(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_s, float32, H1_4, OP)

#define DO_FPCMP_PPZZ_D(NAME, OP) \
    DO_FPCMP_PPZZ(NAME##_d, float64, H1_8, OP)

#define DO_FPCMP_PPZZ_ALL(NAME, OP) \
    DO_FPCMP_PPZZ_H(NAME, OP)   \
    DO_FPCMP_PPZZ_S(NAME, OP)   \
    DO_FPCMP_PPZZ_D(NAME, OP)

#define DO_FACGT(TYPE, X, Y, ST)  \
    TYPE##_compare(TYPE##_abs(Y), TYPE##_abs(X), ST) < 0

DO_FPCMP_PPZZ_ALL(sve_facgt, DO_FACGT)

