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

#define H1_2(x) (x)

#define DO_EOR(N, M)  (N ^ M)

#define DO_ZZZ_NTB(NAME, TYPE, H, OP)                                   \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)          \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    intptr_t sel1 = extract32(desc, SIMD_DATA_SHIFT, 1) * sizeof(TYPE); \
    intptr_t sel2 = extract32(desc, SIMD_DATA_SHIFT + 1, 1) * sizeof(TYPE); \
    for (i = 0; i < opr_sz; i += 2 * sizeof(TYPE)) {                    \
        TYPE nn = *(TYPE *)(vn + H(i + sel1));                          \
        TYPE mm = *(TYPE *)(vm + H(i + sel2));                          \
        *(TYPE *)(vd + H(i + sel1)) = OP(nn, mm);                       \
    }                                                                   \
}

DO_ZZZ_NTB(sve2_eoril_h, uint16_t, H1_2, DO_EOR)

