#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint16_t float16;

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

static inline void set_flush_to_zero(flag val, float_status *status)
{
    status->flush_to_zero = val;
}

static inline flag get_flush_to_zero(float_status *status)
{
    return status->flush_to_zero;
}

float16 float64_to_float16(float64 a, bool ieee, float_status *status);

#define DO_ZPZ_FP(NAME, TYPE, H, OP)                                  \
void HELPER(NAME)(void *vd, void *vn, void *vg, void *status, uint32_t desc) \
{                                                                     \
    intptr_t i = simd_oprsz(desc);                                    \
    uint64_t *g = vg;                                                 \
    do {                                                              \
        uint64_t pg = g[(i - 1) >> 6];                                \
        do {                                                          \
            i -= sizeof(TYPE);                                        \
            if (likely((pg >> (i & 63)) & 1)) {                       \
                TYPE nn = *(TYPE *)(vn + H(i));                       \
                *(TYPE *)(vd + H(i)) = OP(nn, status);                \
            }                                                         \
        } while (i & 63);                                             \
    } while (i != 0);                                                 \
}

static inline float16 sve_f64_to_f16(float64 f, float_status *fpst)
{
    flag save = get_flush_to_zero(fpst);
    float16 ret;

    set_flush_to_zero(false, fpst);
    ret = float64_to_float16(f, true, fpst);
    set_flush_to_zero(save, fpst);
    return ret;
}

DO_ZPZ_FP(sve_fcvt_dh, uint64_t,     , sve_f64_to_f16)

