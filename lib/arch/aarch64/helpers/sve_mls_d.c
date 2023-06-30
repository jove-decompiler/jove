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

#define DO_ZPZZZ_D(NAME, TYPE, OP)                            \
void HELPER(NAME)(void *vd, void *va, void *vn, void *vm,     \
                  void *vg, uint32_t desc)                    \
{                                                             \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                \
    TYPE *d = vd, *a = va, *n = vn, *m = vm;                  \
    uint8_t *pg = vg;                                         \
    for (i = 0; i < opr_sz; i += 1) {                         \
        if (pg[H1(i)] & 1) {                                  \
            TYPE aa = a[i], nn = n[i], mm = m[i];             \
            d[i] = OP(aa, nn, mm);                            \
        }                                                     \
    }                                                         \
}

#define DO_MLS(A, N, M)  (A - N * M)

DO_ZPZZZ_D(sve_mls_d, uint64_t, DO_MLS)

