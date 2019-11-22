#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint64_t rol64(uint64_t word, unsigned int shift)
{
    return (word << shift) | (word >> ((64 - shift) & 63));
}

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

static inline uint64_t hswap64(uint64_t h)
{
    uint64_t m = 0x0000ffff0000ffffull;
    h = rol64(h, 32);
    return ((h & m) << 16) | ((h >> 16) & m);
}

void HELPER(sve_rev_h)(void *vd, void *vn, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    for (i = 0, j = opr_sz - 8; i < opr_sz / 2; i += 8, j -= 8) {
        uint64_t f = *(uint64_t *)(vn + i);
        uint64_t b = *(uint64_t *)(vn + j);
        *(uint64_t *)(vd + i) = hswap64(b);
        *(uint64_t *)(vd + j) = hswap64(f);
    }
}

