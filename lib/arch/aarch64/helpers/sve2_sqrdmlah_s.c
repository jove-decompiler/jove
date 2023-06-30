#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

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

int32_t do_sqrdmlah_s(int32_t src1, int32_t src2, int32_t src3,
                      bool neg, bool round, uint32_t *sat)
{
    /* Simplify similarly to do_sqrdmlah_b above.  */
    int64_t ret = (int64_t)src1 * src2;
    if (neg) {
        ret = -ret;
    }
    ret += ((int64_t)src3 << 31) + (round << 30);
    ret >>= 31;

    if (ret != (int32_t)ret) {
        *sat = 1;
        ret = (ret < 0 ? INT32_MIN : INT32_MAX);
    }
    return ret;
}

void HELPER(sve2_sqrdmlah_s)(void *vd, void *vn, void *vm,
                             void *va, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int32_t *d = vd, *n = vn, *m = vm, *a = va;
    uint32_t discard;

    for (i = 0; i < opr_sz / 4; ++i) {
        d[i] = do_sqrdmlah_s(n[i], m[i], a[i], false, true, &discard);
    }
}

