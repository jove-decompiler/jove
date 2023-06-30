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

void HELPER(gvec_pmul_b)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; ++i) {
        uint64_t nn = n[i];
        uint64_t mm = m[i];
        uint64_t rr = 0;

        for (j = 0; j < 8; ++j) {
            uint64_t mask = (nn & 0x0101010101010101ull) * 0xff;
            rr ^= mm & mask;
            mm = (mm << 1) & 0xfefefefefefefefeull;
            nn >>= 1;
        }
        d[i] = rr;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

