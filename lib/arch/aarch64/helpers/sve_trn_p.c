#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

#include <stdint.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

static const uint64_t even_bit_esz_masks[5] = {
    0x5555555555555555ull,
    0x3333333333333333ull,
    0x0f0f0f0f0f0f0f0full,
    0x00ff00ff00ff00ffull,
    0x0000ffff0000ffffull,
};

void HELPER(sve_trn_p)(void *vd, void *vn, void *vm, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    uintptr_t esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
    bool odd = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1);
    uint64_t *d = vd, *n = vn, *m = vm;
    uint64_t mask;
    int shr, shl;
    intptr_t i;

    shl = 1 << esz;
    shr = 0;
    mask = even_bit_esz_masks[esz];
    if (odd) {
        mask <<= shl;
        shr = shl;
        shl = 0;
    }

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); i++) {
        uint64_t nn = (n[i] & mask) >> shr;
        uint64_t mm = (m[i] & mask) << shl;
        d[i] = nn + mm;
    }
}

