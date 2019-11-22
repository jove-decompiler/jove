#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

typedef uint32_t float32;

#define float32_val(x) (x)

#define make_float32(x) (x)

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

float32 float32_muladd(float32, float32, float32, int, float_status *status);

static inline float32 float32_abs(float32 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float32(float32_val(a) & 0x7fffffff);
}

static inline int float32_is_neg(float32 a)
{
    return float32_val(a) >> 31;
}

void HELPER(sve_ftmad_s)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float32 coeff[16] = {
        0x3f800000, 0xbe2aaaab, 0x3c088886, 0xb95008b9,
        0x36369d6d, 0x00000000, 0x00000000, 0x00000000,
        0x3f800000, 0xbf000000, 0x3d2aaaa6, 0xbab60705,
        0x37cd37cc, 0x00000000, 0x00000000, 0x00000000,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float32);
    intptr_t x = simd_data(desc);
    float32 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float32 mm = m[i];
        intptr_t xx = x;
        if (float32_is_neg(mm)) {
            mm = float32_abs(mm);
            xx += 8;
        }
        d[i] = float32_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

