#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

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

float64 float64_add(float64, float64, float_status *status);

#define H1(x)   (x)

uint64_t HELPER(sve_fadda_d)(uint64_t nn, void *vm, void *vg,
                             void *status, uint32_t desc)
{
    intptr_t i = 0, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i++) {
        if (pg[H1(i)] & 1) {
            nn = float64_add(nn, m[i], status);
        }
    }

    return nn;
}

