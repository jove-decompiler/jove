#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

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

static inline int32_t do_sat_bhs(int64_t val, int64_t min, int64_t max)
{
    return val >= max ? max : val <= min ? min : val;
}

#define DO_XTNB(NAME, TYPE, OP) \
void HELPER(NAME)(void *vd, void *vn, uint32_t desc)         \
{                                                            \
    intptr_t i, opr_sz = simd_oprsz(desc);                   \
    for (i = 0; i < opr_sz; i += sizeof(TYPE)) {             \
        TYPE nn = *(TYPE *)(vn + i);                         \
        nn = OP(nn) & MAKE_64BIT_MASK(0, sizeof(TYPE) * 4);  \
        *(TYPE *)(vd + i) = nn;                              \
    }                                                        \
}

#define DO_SQXTN_D(n)  do_sat_bhs(n, INT32_MIN, INT32_MAX)

DO_XTNB(sve2_sqxtnb_d, int64_t, DO_SQXTN_D)

