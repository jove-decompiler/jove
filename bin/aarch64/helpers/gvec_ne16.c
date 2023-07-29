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

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) * 8 + 8;
}

static inline intptr_t simd_oprsz(uint32_t desc)
{
    uint32_t f = extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS);
    intptr_t o = f * 8 + 8;
    intptr_t m = simd_maxsz(desc);
    return f == 2 ? m : o;
}

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

#define DO_CMP1(NAME, TYPE, OP)                                            \
void HELPER(NAME)(void *d, void *a, void *b, uint32_t desc)                \
{                                                                          \
    intptr_t oprsz = simd_oprsz(desc);                                     \
    intptr_t i;                                                            \
    for (i = 0; i < oprsz; i += sizeof(TYPE)) {                            \
        *(TYPE *)(d + i) = -(*(TYPE *)(a + i) OP *(TYPE *)(b + i));        \
    }                                                                      \
    clear_high(d, oprsz, desc);                                            \
}

#define DO_CMP2(SZ) \
    DO_CMP1(gvec_eq##SZ, uint##SZ##_t, ==)    \
    DO_CMP1(gvec_ne##SZ, uint##SZ##_t, !=)    \
    DO_CMP1(gvec_lt##SZ, int##SZ##_t, <)      \
    DO_CMP1(gvec_le##SZ, int##SZ##_t, <=)     \
    DO_CMP1(gvec_ltu##SZ, uint##SZ##_t, <)    \
    DO_CMP1(gvec_leu##SZ, uint##SZ##_t, <=)

DO_CMP2(16)

