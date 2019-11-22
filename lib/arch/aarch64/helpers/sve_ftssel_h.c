#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define make_float16(x) (x)

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

#define float16_one make_float16(0x3c00)

void HELPER(sve_ftssel_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc) / 2;
    uint16_t *d = vd, *n = vn, *m = vm;
    for (i = 0; i < opr_sz; i += 1) {
        uint16_t nn = n[i];
        uint16_t mm = m[i];
        if (mm & 1) {
            nn = float16_one;
        }
        d[i] = nn ^ (mm & 2) << 14;
    }
}

