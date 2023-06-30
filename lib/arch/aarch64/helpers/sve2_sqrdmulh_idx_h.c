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

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

#define HELPER(name) glue(helper_, name)

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

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

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define H2(x)   (x)

int16_t do_sqrdmlah_h(int16_t src1, int16_t src2, int16_t src3,
                      bool neg, bool round, uint32_t *sat)
{
    /* Simplify similarly to do_sqrdmlah_b above.  */
    int32_t ret = (int32_t)src1 * src2;
    if (neg) {
        ret = -ret;
    }
    ret += ((int32_t)src3 << 15) + (round << 14);
    ret >>= 15;

    if (ret != (int16_t)ret) {
        *sat = 1;
        ret = (ret < 0 ? INT16_MIN : INT16_MAX);
    }
    return ret;
}

void HELPER(sve2_sqrdmulh_idx_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    int idx = simd_data(desc);
    int16_t *d = vd, *n = vn, *m = (int16_t *)vm + H2(idx);
    uint32_t discard;

    for (i = 0; i < opr_sz / 2; i += 16 / 2) {
        int16_t mm = m[i];
        for (j = 0; j < 16 / 2; ++j) {
            d[i + j] = do_sqrdmlah_h(n[i + j], mm, 0, false, true, &discard);
        }
    }
}

