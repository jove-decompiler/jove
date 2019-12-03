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

#define H1(x)   (x)

#define DO_ZIP(NAME, TYPE, H) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)       \
{                                                                    \
    intptr_t oprsz = simd_oprsz(desc);                               \
    intptr_t i, oprsz_2 = oprsz / 2;                                 \
    ARMVectorReg tmp_n, tmp_m;                                       \
    /* We produce output faster than we consume input.               \
       Therefore we must be mindful of possible overlap.  */         \
    if (unlikely((vn - vd) < (uintptr_t)oprsz)) {                    \
        vn = __builtin_memcpy(&tmp_n, vn, oprsz_2);                            \
    }                                                                \
    if (unlikely((vm - vd) < (uintptr_t)oprsz)) {                    \
        vm = __builtin_memcpy(&tmp_m, vm, oprsz_2);                            \
    }                                                                \
    for (i = 0; i < oprsz_2; i += sizeof(TYPE)) {                    \
        *(TYPE *)(vd + H(2 * i + 0)) = *(TYPE *)(vn + H(i));         \
        *(TYPE *)(vd + H(2 * i + sizeof(TYPE))) = *(TYPE *)(vm + H(i)); \
    }                                                                \
}

DO_ZIP(sve_zip_b, uint8_t, H1)

