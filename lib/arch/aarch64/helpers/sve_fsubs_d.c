#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint64_t float64;

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

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

float64 float64_sub(float64, float64, float_status *status);

#define DO_ZPZS_FP(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint64_t scalar,  \
                  void *status, uint32_t desc)                    \
{                                                                 \
    intptr_t i = simd_oprsz(desc);                                \
    uint64_t *g = vg;                                             \
    TYPE mm = scalar;                                             \
    do {                                                          \
        uint64_t pg = g[(i - 1) >> 6];                            \
        do {                                                      \
            i -= sizeof(TYPE);                                    \
            if (likely((pg >> (i & 63)) & 1)) {                   \
                TYPE nn = *(TYPE *)(vn + H(i));                   \
                *(TYPE *)(vd + H(i)) = OP(nn, mm, status);        \
            }                                                     \
        } while (i & 63);                                         \
    } while (i != 0);                                             \
}

DO_ZPZS_FP(sve_fsubs_d, float64,     , float64_sub)

