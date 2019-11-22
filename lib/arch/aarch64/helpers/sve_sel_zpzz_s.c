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

static inline uint64_t expand_pred_s(uint8_t byte)
{
    static const uint64_t word[] = {
        [0x01] = 0x00000000ffffffffull,
        [0x10] = 0xffffffff00000000ull,
        [0x11] = 0xffffffffffffffffull,
    };
    return word[byte & 0x11];
}

void HELPER(sve_sel_zpzz_s)(void *vd, void *vn, void *vm,
                            void *vg, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;
    uint64_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    for (i = 0; i < opr_sz; i += 1) {
        uint64_t nn = n[i], mm = m[i];
        uint64_t pp = expand_pred_s(pg[H1(i)]);
        d[i] = (nn & pp) | (mm & ~pp);
    }
}

