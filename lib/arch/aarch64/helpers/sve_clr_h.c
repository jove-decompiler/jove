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

static inline uint64_t expand_pred_h(uint8_t byte)
{
    static const uint64_t word[] = {
        [0x01] = 0x000000000000ffff, [0x04] = 0x00000000ffff0000,
        [0x05] = 0x00000000ffffffff, [0x10] = 0x0000ffff00000000,
        [0x11] = 0x0000ffff0000ffff, [0x14] = 0x0000ffffffff0000,
        [0x15] = 0x0000ffffffffffff, [0x40] = 0xffff000000000000,
        [0x41] = 0xffff00000000ffff, [0x44] = 0xffff0000ffff0000,
        [0x45] = 0xffff0000ffffffff, [0x50] = 0xffffffff00000000,
        [0x51] = 0xffffffff0000ffff, [0x54] = 0xffffffffffff0000,
        [0x55] = 0xffffffffffffffff,
    };
    return word[byte & 0x55];
}

void HELPER(sve_clr_h)(void *vd, void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd;
    uint8_t *pg = vg;
    for (i = 0; i < opr_sz; i += 1) {
        d[i] &= ~expand_pred_h(pg[H1(i)]);
    }
}

