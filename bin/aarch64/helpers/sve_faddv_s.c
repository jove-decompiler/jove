#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

typedef uint32_t float32;

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

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

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

float32 float32_add(float32, float32, float_status *status);

#define float32_zero make_float32(0)

#define H1_2(x) (x)

#define H1_4(x) (x)

#define DO_REDUCE(NAME, TYPE, H, FUNC, IDENT)                         \
static TYPE NAME##_reduce(TYPE *data, float_status *status, uintptr_t n) \
{                                                                     \
    if (n == 1) {                                                     \
        return *data;                                                 \
    } else {                                                          \
        uintptr_t half = n / 2;                                       \
        TYPE lo = NAME##_reduce(data, status, half);                  \
        TYPE hi = NAME##_reduce(data + half, status, half);           \
        return TYPE##_##FUNC(lo, hi, status);                         \
    }                                                                 \
}                                                                     \
uint64_t HELPER(NAME)(void *vn, void *vg, void *vs, uint32_t desc)    \
{                                                                     \
    uintptr_t i, oprsz = simd_oprsz(desc), maxsz = simd_data(desc);   \
    TYPE data[sizeof(ARMVectorReg) / sizeof(TYPE)];                   \
    for (i = 0; i < oprsz; ) {                                        \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));               \
        do {                                                          \
            TYPE nn = *(TYPE *)(vn + H(i));                           \
            *(TYPE *)((void *)data + i) = (pg & 1 ? nn : IDENT);      \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                   \
        } while (i & 15);                                             \
    }                                                                 \
    for (; i < maxsz; i += sizeof(TYPE)) {                            \
        *(TYPE *)((void *)data + i) = IDENT;                          \
    }                                                                 \
    return NAME##_reduce(data, vs, maxsz / sizeof(TYPE));             \
}

DO_REDUCE(sve_faddv_s, float32, H1_4, add, float32_zero)

