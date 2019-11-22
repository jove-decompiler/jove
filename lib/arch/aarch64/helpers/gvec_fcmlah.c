#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint16_t float16;

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

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

float16 float16_muladd(float16, float16, float16, int, float_status *status);

#define H2(x)  (x)

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_fcmlah)(void *vd, void *vn, void *vm,
                         void *vfpst, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    float16 *d = vd;
    float16 *n = vn;
    float16 *m = vm;
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

        d[H2(i)] = float16_muladd(e2, e1, d[H2(i)], 0, fpst);
        d[H2(i + 1)] = float16_muladd(e4, e3, d[H2(i + 1)], 0, fpst);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

