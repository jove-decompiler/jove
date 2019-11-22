#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static inline int ctpop64(uint64_t val)
{
    return __builtin_popcountll(val);
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

extern const uint64_t pred_esz_masks[4];

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

uint64_t HELPER(sve_cntp)(void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    uint64_t *n = vn, *g = vg, sum = 0, mask = pred_esz_masks[esz];
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t t = n[i] & g[i] & mask;
        sum += ctpop64(t);
    }
    return sum;
}

