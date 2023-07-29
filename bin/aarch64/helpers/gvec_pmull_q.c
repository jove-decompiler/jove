#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline int32_t sextract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    /* Note that this implementation relies on right shift of signed
     * integers being an arithmetic shift.
     */
    return ((int32_t)(value << (32 - length - start))) >> (32 - length);
}

#define HELPER(name) glue(helper_, name)

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

#define SIMD_DATA_SHIFT    (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

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

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_pmull_q)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, j, opr_sz = simd_oprsz(desc);
    intptr_t hi = simd_data(desc);
    uint64_t *d = vd, *n = vn, *m = vm;

    for (i = 0; i < opr_sz / 8; i += 2) {
        uint64_t nn = n[i + hi];
        uint64_t mm = m[i + hi];
        uint64_t rhi = 0;
        uint64_t rlo = 0;

        /* Bit 0 can only influence the low 64-bit result.  */
        if (nn & 1) {
            rlo = mm;
        }

        for (j = 1; j < 64; ++j) {
            uint64_t mask = -((nn >> j) & 1);
            rlo ^= (mm << j) & mask;
            rhi ^= (mm >> (64 - j)) & mask;
        }
        d[i] = rlo;
        d[i + 1] = rhi;
    }
    clear_tail(d, opr_sz, simd_maxsz(desc));
}

