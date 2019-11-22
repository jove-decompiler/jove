#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint8_t flag;

#define float64_val(x) (x)

#define make_float64(x) (x)

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

float64 float64_muladd(float64, float64, float64, int, float_status *status);

static inline float64 float64_abs(float64 a)
{
    /* Note that abs does *not* handle NaN specially, nor does
     * it flush denormal inputs to zero.
     */
    return make_float64(float64_val(a) & 0x7fffffffffffffffLL);
}

static inline int float64_is_neg(float64 a)
{
    return float64_val(a) >> 63;
}

void HELPER(sve_ftmad_d)(void *vd, void *vn, void *vm, void *vs, uint32_t desc)
{
    static const float64 coeff[16] = {
        0x3ff0000000000000ull, 0xbfc5555555555543ull,
        0x3f8111111110f30cull, 0xbf2a01a019b92fc6ull,
        0x3ec71de351f3d22bull, 0xbe5ae5e2b60f7b91ull,
        0x3de5d8408868552full, 0x0000000000000000ull,
        0x3ff0000000000000ull, 0xbfe0000000000000ull,
        0x3fa5555555555536ull, 0xbf56c16c16c13a0bull,
        0x3efa01a019b1e8d8ull, 0xbe927e4f7282f468ull,
        0x3e21ee96d2641b13ull, 0xbda8f76380fbb401ull,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(float64);
    intptr_t x = simd_data(desc);
    float64 *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i++) {
        float64 mm = m[i];
        intptr_t xx = x;
        if (float64_is_neg(mm)) {
            mm = float64_abs(mm);
            xx += 8;
        }
        d[i] = float64_muladd(n[i], mm, coeff[xx], 0, vs);
    }
}

