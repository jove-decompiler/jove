#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <string.h>

#include <assert.h>

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

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H2(x)   (x)

#define H4(x)   (x)

#define DO_UNPK(NAME, TYPED, TYPES, HD, HS) \
void HELPER(NAME)(void *vd, void *vn, uint32_t desc)           \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    TYPED *d = vd;                                             \
    TYPES *n = vn;                                             \
    ARMVectorReg tmp;                                          \
    if (unlikely(vn - vd < opr_sz)) {                          \
        n = __builtin_memcpy(&tmp, n, opr_sz / 2);                       \
    }                                                          \
    for (i = 0; i < opr_sz / sizeof(TYPED); i++) {             \
        d[HD(i)] = n[HS(i)];                                   \
    }                                                          \
}

DO_UNPK(sve_sunpk_s, int32_t, int16_t, H4, H2)

