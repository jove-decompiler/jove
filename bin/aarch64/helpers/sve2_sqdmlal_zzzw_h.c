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

#define H1(x)   (x)

#define H1_2(x) (x)

#define DO_SQADD_H(n, m) do_sat_bhs((int64_t)n + m, INT16_MIN, INT16_MAX)

static inline int32_t do_sat_bhs(int64_t val, int64_t min, int64_t max)
{
    return val >= max ? max : val <= min ? min : val;
}

static inline int16_t do_sqdmull_h(int16_t n, int16_t m)
{
    int16_t val = n * m;
    return DO_SQADD_H(val, val);
}

#define DO_SQDMLAL(NAME, TYPEW, TYPEN, HW, HN, DMUL_OP, SUM_OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    int sel1 = extract32(desc, SIMD_DATA_SHIFT, 1) * sizeof(TYPEN);     \
    int sel2 = extract32(desc, SIMD_DATA_SHIFT + 1, 1) * sizeof(TYPEN); \
    for (i = 0; i < opr_sz; i += sizeof(TYPEW)) {                       \
        TYPEW nn = *(TYPEN *)(vn + HN(i + sel1));                       \
        TYPEW mm = *(TYPEN *)(vm + HN(i + sel2));                       \
        TYPEW aa = *(TYPEW *)(va + HW(i));                              \
        *(TYPEW *)(vd + HW(i)) = SUM_OP(aa, DMUL_OP(nn, mm));           \
    }                                                                   \
}

DO_SQDMLAL(sve2_sqdmlal_zzzw_h, int16_t, int8_t, H1_2, H1,
           do_sqdmull_h, DO_SQADD_H)

