#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define unlikely(x)   __builtin_expect(!!(x), 0)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

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

typedef uint64_t vec64 __attribute__((vector_size(16)));

#define DUP2(X)   { X, X }

static inline void clear_high(void *d, intptr_t oprsz, uint32_t desc)
{
    intptr_t maxsz = simd_maxsz(desc);
    intptr_t i;

    if (unlikely(maxsz > oprsz)) {
        for (i = oprsz; i < maxsz; i += sizeof(uint64_t)) {
            *(uint64_t *)(d + i) = 0;
        }
    }
}

void HELPER(gvec_subs64)(void *d, void *a, uint64_t b, uint32_t desc)
{
    intptr_t oprsz = simd_oprsz(desc);
    vec64 vecb = (vec64)DUP2(b);
    intptr_t i;

    for (i = 0; i < oprsz; i += sizeof(vec64)) {
        *(vec64 *)(d + i) = *(vec64 *)(a + i) - vecb;
    }
    clear_high(d, oprsz, desc);
}

