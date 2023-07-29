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

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

#define DO_DOT(NAME, TYPED, TYPEN, TYPEM) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc)  \
{                                                                         \
    intptr_t i, opr_sz = simd_oprsz(desc);                                \
    TYPED *d = vd, *a = va;                                               \
    TYPEN *n = vn;                                                        \
    TYPEM *m = vm;                                                        \
    for (i = 0; i < opr_sz / sizeof(TYPED); ++i) {                        \
        d[i] = (a[i] +                                                    \
                (TYPED)n[i * 4 + 0] * m[i * 4 + 0] +                      \
                (TYPED)n[i * 4 + 1] * m[i * 4 + 1] +                      \
                (TYPED)n[i * 4 + 2] * m[i * 4 + 2] +                      \
                (TYPED)n[i * 4 + 3] * m[i * 4 + 3]);                      \
    }                                                                     \
    clear_tail(d, opr_sz, simd_maxsz(desc));                              \
}

DO_DOT(gvec_udot_b, uint32_t, uint8_t, uint8_t)

