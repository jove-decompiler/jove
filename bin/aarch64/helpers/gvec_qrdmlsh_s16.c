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

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

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

void HELPER(gvec_qrdmlsh_s16)(void *vd, void *vn, void *vm,
                              void *vq, uint32_t desc)
{
    uintptr_t opr_sz = simd_oprsz(desc);
    int16_t *d = vd;
    int16_t *n = vn;
    int16_t *m = vm;
    uintptr_t i;

    for (i = 0; i < opr_sz / 2; ++i) {
        d[i] = do_sqrdmlah_h(n[i], m[i], d[i], true, true, vq);
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

