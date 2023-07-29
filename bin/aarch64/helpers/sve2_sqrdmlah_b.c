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

int8_t do_sqrdmlah_b(int8_t src1, int8_t src2, int8_t src3,
                     bool neg, bool round)
{
    /*
     * Simplify:
     * = ((a3 << 8) + ((e1 * e2) << 1) + (round << 7)) >> 8
     * = ((a3 << 7) + (e1 * e2) + (round << 6)) >> 7
     */
    int32_t ret = (int32_t)src1 * src2;
    if (neg) {
        ret = -ret;
    }
    ret += ((int32_t)src3 << 7) + (round << 6);
    ret >>= 7;

    if (ret != (int8_t)ret) {
        ret = (ret < 0 ? INT8_MIN : INT8_MAX);
    }
    return ret;
}

void HELPER(sve2_sqrdmlah_b)(void *vd, void *vn, void *vm,
                             void *va, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int8_t *d = vd, *n = vn, *m = vm, *a = va;

    for (i = 0; i < opr_sz; ++i) {
        d[i] = do_sqrdmlah_b(n[i], m[i], a[i], false, true);
    }
}

