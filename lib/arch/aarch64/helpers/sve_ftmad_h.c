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

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

float16 float16_muladd(float16, float16, float16, int, float_status *status);

static inline int float16_is_neg(float16 a)
{
    return float16_val(a) >> 15;
}

static inline float16 float16_abs(float16 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float16(float16_val(a) & 0x7fff);
}

void HELPER(sve_ftmad_h)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float16 coeff[16] = {
        0x3c00, 0xb155, 0x2030, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
        0x3c00, 0xb800, 0x293a, 0x0000, 0x0000, 0x0000, 0x0000, 0x0000,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float16);
    intptr_t x = simd_data(desc);
    float16 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float16 mm = m[i];
        intptr_t xx = x;
        if (float16_is_neg(mm)) {
            mm = float16_abs(mm);
            xx += 8;
        }
        d[i] = float16_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

