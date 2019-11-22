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

#define H4(x)   (x)

#define DO_TBL(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    uintptr_t elem = opr_sz / sizeof(TYPE);                    \
    TYPE *d = vd, *n = vn, *m = vm;                            \
    ARMVectorReg tmp;                                          \
    if (unlikely(vd == vn)) {                                  \
        n = memcpy(&tmp, vn, opr_sz);                          \
    }                                                          \
    for (i = 0; i < elem; i++) {                               \
        TYPE j = m[H(i)];                                      \
        d[H(i)] = j < elem ? n[H(j)] : 0;                      \
    }                                                          \
}

DO_TBL(sve_tbl_s, uint32_t, H4)

