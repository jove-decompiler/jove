#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint32_t float32;

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

float32 float32_muladd(float32, float32, float32, int, float_status *status);

#define H4(x)  (x)

#define DO_FMLA_IDX(NAME, TYPE, H)                                         \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va,                  \
                  void *stat, uint32_t desc)                               \
{                                                                          \
    intptr_t i, j, oprsz = simd_oprsz(desc), segment = 16 / sizeof(TYPE);  \
    TYPE op1_neg = extract32(desc, SIMD_DATA_SHIFT, 1);                    \
    intptr_t idx = desc >> (SIMD_DATA_SHIFT + 1);                          \
    TYPE *d = vd, *n = vn, *m = vm, *a = va;                               \
    op1_neg <<= (8 * sizeof(TYPE) - 1);                                    \
    for (i = 0; i < oprsz / sizeof(TYPE); i += segment) {                  \
        TYPE mm = m[H(i + idx)];                                           \
        for (j = 0; j < segment; j++) {                                    \
            d[i + j] = TYPE##_muladd(n[i + j] ^ op1_neg,                   \
                                     mm, a[i + j], 0, stat);               \
        }                                                                  \
    }                                                                      \
}

DO_FMLA_IDX(gvec_fmla_idx_s, float32, H4)

