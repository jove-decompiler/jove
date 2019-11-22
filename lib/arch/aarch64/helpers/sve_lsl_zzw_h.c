#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1_2(x) (x)

#define DO_LSL(N, M)  (M < sizeof(N) * 8 ? N << M : 0)

#define DO_ZZW(NAME, TYPE, TYPEW, H, OP)                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc) \
{                                                              \
    intptr_t i, opr_sz = simd_oprsz(desc);                     \
    for (i = 0; i < opr_sz; ) {                                \
        TYPEW mm = *(TYPEW *)(vm + i);                         \
        do {                                                   \
            TYPE nn = *(TYPE *)(vn + H(i));                    \
            *(TYPE *)(vd + H(i)) = OP(nn, mm);                 \
            i += sizeof(TYPE);                                 \
        } while (i & 7);                                       \
    }                                                          \
}

DO_ZZW(sve_lsl_zzw_h, uint16_t, uint64_t, H1_2, DO_LSL)

