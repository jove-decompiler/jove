#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })

typedef uint32_t float32;

#define float_tininess_before_rounding true

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

#define HELPER(name) glue(helper_, name)

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

float32 float32_add(float32, float32, float_status *status);

float32 float32_mul(float32, float32, float_status *status);

#define H4(x)   (x)

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

float32 bfdotadd(float32 sum, uint32_t e1, uint32_t e2)
{
    /* FPCR is ignored for BFDOT and BFMMLA. */
    float_status bf_status = {
        .tininess_before_rounding = float_tininess_before_rounding,
        .float_rounding_mode = float_round_to_odd_inf,
        .flush_to_zero = true,
        .flush_inputs_to_zero = true,
        .default_nan_mode = true,
    };
    float32 t1, t2;

    /*
     * Extract each BFloat16 from the element pair, and shift
     * them such that they become float32.
     */
    t1 = float32_mul(e1 << 16, e2 << 16, &bf_status);
    t2 = float32_mul(e1 & 0xffff0000u, e2 & 0xffff0000u, &bf_status);
    t1 = float32_add(t1, t2, &bf_status);
    t1 = float32_add(sum, t1, &bf_status);

    return t1;
}

void HELPER(gvec_bfdot_idx)(void *vd, void *vn, void *vm,
                            void *va, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    intptr_t index = simd_data(desc);
    intptr_t elements = opr_sz / 4;
    intptr_t eltspersegment = MIN(16 / 4, elements);
    float32 *d = vd, *a = va;
    uint32_t *n = vn, *m = vm;

    for (i = 0; i < elements; i += eltspersegment) {
        uint32_t m_idx = m[i + H4(index)];

        for (j = i; j < i + eltspersegment; j++) {
            d[j] = bfdotadd(a[j], n[j], m_idx);
        }
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

