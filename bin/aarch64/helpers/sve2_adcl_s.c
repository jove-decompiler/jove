#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

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

#define H4(x)   (x)

void HELPER(sve2_adcl_s)(void *vd, void *vn, void *vm, void *va, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);
    int sel = H4(extract32(desc, SIMD_DATA_SHIFT, 1));
    uint32_t inv = -extract32(desc, SIMD_DATA_SHIFT + 1, 1);
    uint32_t *a = va, *n = vn;
    uint64_t *d = vd, *m = vm;

    for (i = 0; i < opr_sz / 8; ++i) {
        uint32_t e1 = a[2 * i + H4(0)];
        uint32_t e2 = n[2 * i + sel] ^ inv;
        uint64_t c = extract64(m[i], 32, 1);
        /* Compute and store the entire 33-bit result at once. */
        d[i] = c + e1 + e2;
    }
}

