#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

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

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

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

float16 float16_maxnum(float16, float16, float_status *status);

#define H1_2(x) (x)

#define DO_REDUCE(NAME, TYPE, H, FUNC, IDENT)                         \
static TYPE NAME##_reduce(TYPE *data, float_status *status, uintptr_t n) \
{                                                                     \
    if (n == 1) {                                                     \
        return *data;                                                 \
    } else {                                                          \
        uintptr_t half = n / 2;                                       \
        TYPE lo = NAME##_reduce(data, status, half);                  \
        TYPE hi = NAME##_reduce(data + half, status, half);           \
        return TYPE##_##FUNC(lo, hi, status);                         \
    }                                                                 \
}                                                                     \
uint64_t HELPER(NAME)(void *vn, void *vg, void *vs, uint32_t desc)    \
{                                                                     \
    uintptr_t i, oprsz = simd_oprsz(desc), maxsz = simd_maxsz(desc);  \
    TYPE data[sizeof(ARMVectorReg) / sizeof(TYPE)];                   \
    for (i = 0; i < oprsz; ) {                                        \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));               \
        do {                                                          \
            TYPE nn = *(TYPE *)(vn + H(i));                           \
            *(TYPE *)((void *)data + i) = (pg & 1 ? nn : IDENT);      \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                   \
        } while (i & 15);                                             \
    }                                                                 \
    for (; i < maxsz; i += sizeof(TYPE)) {                            \
        *(TYPE *)((void *)data + i) = IDENT;                          \
    }                                                                 \
    return NAME##_reduce(data, vs, maxsz / sizeof(TYPE));             \
}

DO_REDUCE(sve_fmaxnmv_h, float16, H1_2, maxnum, 0x7E00)

