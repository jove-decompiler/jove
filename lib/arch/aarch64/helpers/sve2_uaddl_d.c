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

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

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

#define H1_4(x) (x)

#define H1_8(x) (x)

#define DO_ADD(N, M)  (N + M)

#define DO_ZZZ_TB(NAME, TYPEW, TYPEN, HW, HN, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)          \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    int sel1 = extract32(desc, SIMD_DATA_SHIFT, 1) * sizeof(TYPEN);     \
    int sel2 = extract32(desc, SIMD_DATA_SHIFT + 1, 1) * sizeof(TYPEN); \
    for (i = 0; i < opr_sz; i += sizeof(TYPEW)) {                       \
        TYPEW nn = *(TYPEN *)(vn + HN(i + sel1));                       \
        TYPEW mm = *(TYPEN *)(vm + HN(i + sel2));                       \
        *(TYPEW *)(vd + HW(i)) = OP(nn, mm);                            \
    }                                                                   \
}

DO_ZZZ_TB(sve2_uaddl_d, uint64_t, uint32_t, H1_8, H1_4, DO_ADD)

