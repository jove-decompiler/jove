#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint16_t float16;

#define float16_val(x) (x)

#define make_float16(x) (x)

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

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

float16 float16_mul(float16, float16, float_status *status);

static inline int float16_is_any_nan(float16 a)
{
    return ((float16_val(a) & ~0x8000) > 0x7c00);
}

static inline float16 float16_set_sign(float16 a, int sign)
{
    return make_float16((float16_val(a) & 0x7fff) | (sign << 15));
}

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

static float16 float16_ftsmul(float16 op1, uint16_t op2, float_status *stat)
{
    float16 result = float16_mul(op1, op1, stat);
    if (!float16_is_any_nan(result)) {
        result = float16_set_sign(result, op2 & 1);
    }
    return result;
}

#define DO_3OP(NAME, FUNC, TYPE) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *stat, uint32_t desc) \
{                                                                          \
    intptr_t i, oprsz = simd_oprsz(desc);                                  \
    TYPE *d = vd, *n = vn, *m = vm;                                        \
    for (i = 0; i < oprsz / sizeof(TYPE); i++) {                           \
        d[i] = FUNC(n[i], m[i], stat);                                     \
    }                                                                      \
    clear_tail(d, oprsz, simd_maxsz(desc));                                \
}

DO_3OP(gvec_ftsmul_h, float16_ftsmul, float16)

