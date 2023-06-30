#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

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

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

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

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define HELPER(name) glue(helper_, name)

#define H1_4(x) (x)

#define H1_8(x) (x)

#define DO_MUL(N, M)  (N * M)

#define DO_ZZZW_ACC(NAME, TYPEW, TYPEN, HW, HN, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc);                      \
    intptr_t sel1 = simd_data(desc) * sizeof(TYPEN);            \
    for (i = 0; i < opr_sz; i += sizeof(TYPEW)) {               \
        TYPEW nn = *(TYPEN *)(vn + HN(i + sel1));               \
        TYPEW mm = *(TYPEN *)(vm + HN(i + sel1));               \
        TYPEW aa = *(TYPEW *)(va + HW(i));                      \
        *(TYPEW *)(vd + HW(i)) = OP(nn, mm) + aa;               \
    }                                                           \
}

DO_ZZZW_ACC(sve2_umlal_zzzw_d, uint64_t, uint32_t, H1_8, H1_4, DO_MUL)

