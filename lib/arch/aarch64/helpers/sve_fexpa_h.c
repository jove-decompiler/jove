#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

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

#define HELPER(name) glue(helper_, name)

void HELPER(sve_fexpa_h)(void *vd, void *vn, uint32_t desc)
{
    /* These constants are cut-and-paste directly from the ARM pseudocode.  */
    static const uint16_t coeff[] = {
        0x0000, 0x0016, 0x002d, 0x0045, 0x005d, 0x0075, 0x008e, 0x00a8,
        0x00c2, 0x00dc, 0x00f8, 0x0114, 0x0130, 0x014d, 0x016b, 0x0189,
        0x01a8, 0x01c8, 0x01e8, 0x0209, 0x022b, 0x024e, 0x0271, 0x0295,
        0x02ba, 0x02e0, 0x0306, 0x032e, 0x0356, 0x037f, 0x03a9, 0x03d4,
    };
    intptr_t i, opr_sz = simd_oprsz(desc) / 2;
    uint16_t *d = vd, *n = vn;

    for (i = 0; i < opr_sz; i++) {
        uint16_t nn = n[i];
        intptr_t idx = extract32(nn, 0, 5);
        uint16_t exp = extract32(nn, 5, 5);
        d[i] = coeff[idx] | (exp << 10);
    }
}

