#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

enum {
    float_flag_invalid   =  1,
    float_flag_divbyzero =  4,
    float_flag_overflow  =  8,
    float_flag_underflow = 16,
    float_flag_inexact   = 32,
    float_flag_input_denormal = 64,
    float_flag_output_denormal = 128
};

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

void float_raise(uint8_t flags, float_status *status);

int16_t float16_to_int16_round_to_zero(float16, float_status *status);

static inline int float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

#define H1_2(x) (x)

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

static inline int16_t vfp_float16_to_int16_rtz(float16 f, float_status *s)
{
    if (float16_is_any_nan(f)) {
        float_raise(float_flag_invalid, s);
        return 0;
    }
    return float16_to_int16_round_to_zero(f, s);
}

DO_ZPZ_FP(sve_fcvtzs_hh, uint16_t, H1_2, vfp_float16_to_int16_rtz)

