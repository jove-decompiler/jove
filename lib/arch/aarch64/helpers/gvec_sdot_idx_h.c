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

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_sdot_idx_h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc), opr_sz_8 = opr_sz / 8;
    intptr_t index = simd_data(desc);
    uint64_t *d = vd;
    int16_t *n = vn;
    int16_t *m_indexed = (int16_t *)vm + index * 4;

    /* This is supported by SVE only, so opr_sz is always a multiple of 16.
     * Process the entire segment all at once, writing back the results
     * only after we've consumed all of the inputs.
     */
    for (i = 0; i < opr_sz_8 ; i += 2) {
        uint64_t d0, d1;

        d0  = n[i * 4 + 0] * (int64_t)m_indexed[i * 4 + 0];
        d0 += n[i * 4 + 1] * (int64_t)m_indexed[i * 4 + 1];
        d0 += n[i * 4 + 2] * (int64_t)m_indexed[i * 4 + 2];
        d0 += n[i * 4 + 3] * (int64_t)m_indexed[i * 4 + 3];
        d1  = n[i * 4 + 4] * (int64_t)m_indexed[i * 4 + 0];
        d1 += n[i * 4 + 5] * (int64_t)m_indexed[i * 4 + 1];
        d1 += n[i * 4 + 6] * (int64_t)m_indexed[i * 4 + 2];
        d1 += n[i * 4 + 7] * (int64_t)m_indexed[i * 4 + 3];

        d[i + 0] += d0;
        d[i + 1] += d1;
    }

    clear_tail(d, opr_sz, simd_maxsz(desc));
}

