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

void HELPER(gvec_sshl_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int16_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 2; ++i) {
        int8_t mm = m[i];   /* only 8 bits of shift are significant */
        int16_t nn = n[i];
        int16_t res = 0;
        if (mm >= 0) {
            if (mm < 16) {
                res = nn << mm;
            }
        } else {
            res = nn >> (mm > -16 ? -mm : 15);
        }
        d[i] = res;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

