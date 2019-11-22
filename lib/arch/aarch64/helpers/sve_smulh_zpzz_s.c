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

#define H1_4(x) (x)

#define DO_ZPZZ(NAME, TYPE, H, OP)                                       \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                       \
    intptr_t i, opr_sz = simd_oprsz(desc);                              \
    for (i = 0; i < opr_sz; ) {                                         \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));                 \
        do {                                                            \
            if (pg & 1) {                                               \
                TYPE nn = *(TYPE *)(vn + H(i));                         \
                TYPE mm = *(TYPE *)(vm + H(i));                         \
                *(TYPE *)(vd + H(i)) = OP(nn, mm);                      \
            }                                                           \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);                     \
        } while (i & 15);                                               \
    }                                                                   \
}

static inline uint32_t do_mulh_s(int64_t n, int64_t m)
{
    return (n * m) >> 32;
}

DO_ZPZZ(sve_smulh_zpzz_s, int32_t, H1_4, do_mulh_s)

