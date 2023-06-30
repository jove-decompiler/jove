#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

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

#define HELPER(name) glue(helper_, name)

#define DO_BITPERM(NAME, TYPE, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    for (i = 0; i < opr_sz; i += sizeof(TYPE)) {               \
        TYPE nn = *(TYPE *)(vn + i);                           \
        TYPE mm = *(TYPE *)(vm + i);                           \
        *(TYPE *)(vd + i) = OP(nn, mm, sizeof(TYPE) * 8);      \
    }                                                          \
}

static uint64_t bitextract(uint64_t data, uint64_t mask, int n)
{
    uint64_t res = 0;
    int db, rb = 0;

    for (db = 0; db < n; ++db) {
        if ((mask >> db) & 1) {
            res |= ((data >> db) & 1) << rb;
            ++rb;
        }
    }
    return res;
}

DO_BITPERM(sve2_bext_d, uint64_t, bitextract)

