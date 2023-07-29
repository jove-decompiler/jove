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

static inline int64_t do_sqadd_d(int64_t n, int64_t m)
{
    int64_t r = n + m;
    if (((r ^ n) & ~(n ^ m)) < 0) {
        /* Signed overflow.  */
        return r < 0 ? INT64_MAX : INT64_MIN;
    }
    return r;
}

void HELPER(sve_sqaddi_d)(void *d, void *a, int64_t b, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);

    for (i = 0; i < oprsz; i += sizeof(int64_t)) {
        *(int64_t *)(d + i) = do_sqadd_d(b, *(int64_t *)(a + i));
    }
}

