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

#define H1_2(x) (x)

#define H1_4(x) (x)

#define DO_AND(N, M)  (N & M)

#define DO_VPZ(NAME, TYPEELT, TYPERED, TYPERET, H, INIT, OP) \
uint64_t HELPER(NAME)(void *vn, void *vg, uint32_t desc)   \
{                                                          \
    intptr_t i, opr_sz = simd_oprsz(desc);                 \
    TYPERED ret = INIT;                                    \
    for (i = 0; i < opr_sz; ) {                            \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));    \
        do {                                               \
            if (pg & 1) {                                  \
                TYPEELT nn = *(TYPEELT *)(vn + H(i));      \
                ret = OP(ret, nn);                         \
            }                                              \
            i += sizeof(TYPEELT), pg >>= sizeof(TYPEELT);  \
        } while (i & 15);                                  \
    }                                                      \
    return (TYPERET)ret;                                   \
}

DO_VPZ(sve_andv_s, uint32_t, uint32_t, uint32_t, H1_4, -1, DO_AND)

