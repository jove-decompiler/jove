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

#define H1(x)   (x)

#define DO_ADD(N, M)  (N + M)

#define DO_ZPZZ_PAIR_D(NAME, TYPE, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn, *m = vm;                             \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 2) {                           \
        TYPE n0 = n[i], n1 = n[i + 1];                          \
        TYPE m0 = m[i], m1 = m[i + 1];                          \
        if (pg[H1(i)] & 1) {                                    \
            d[i] = OP(n0, n1);                                  \
        }                                                       \
        if (pg[H1(i + 1)] & 1) {                                \
            d[i + 1] = OP(m0, m1);                              \
        }                                                       \
    }                                                           \
}

DO_ZPZZ_PAIR_D(sve2_addp_zpzz_d, uint64_t, DO_ADD)

