#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

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

#define H1(x)   (x)

#define H1_2(x) (x)

static inline int32_t do_sat_bhs(int64_t val, int64_t min, int64_t max)
{
    return val >= max ? max : val <= min ? min : val;
}

static inline int64_t do_srshr(int64_t x, unsigned sh)
{
    if (likely(sh < 64)) {
        return (x >> sh) + ((x >> (sh - 1)) & 1);
    } else {
        /* Rounding the sign bit always produces 0. */
        return 0;
    }
}

#define DO_SHRNT(NAME, TYPEW, TYPEN, HW, HN, OP)                  \
void HELPER(NAME)(void *vd, void *vn, uint32_t desc)              \
{                                                                 \
    intptr_t i, opr_sz = simd_oprsz(desc);                        \
    int shift = simd_data(desc);                                  \
    for (i = 0; i < opr_sz; i += sizeof(TYPEW)) {                 \
        TYPEW nn = *(TYPEW *)(vn + HW(i));                        \
        *(TYPEN *)(vd + HN(i + sizeof(TYPEN))) = OP(nn, shift);   \
    }                                                             \
}

#define DO_SQRSHRUN_H(x, sh) do_sat_bhs(do_srshr(x, sh), 0, UINT8_MAX)

DO_SHRNT(sve2_sqrshrunt_h, int16_t, uint8_t, H1_2, H1, DO_SQRSHRUN_H)

