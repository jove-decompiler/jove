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

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1(x)   (x)

void HELPER(sve_compact_d)(void *vd, void *vn, void *vg, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn;
    uint8_t *pg = vg;

    for (i = j = 0; i < opr_sz; i++) {
        if (pg[H1(i)] & 1) {
            d[j] = n[i];
            j++;
        }
    }
    for (; j < opr_sz; j++) {
        d[j] = 0;
    }
}

