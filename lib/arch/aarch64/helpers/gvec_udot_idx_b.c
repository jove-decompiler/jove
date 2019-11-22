#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define MIN(a, b)  (((a) < (b)) ? (a) : (b))

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

void HELPER(gvec_udot_idx_b)(void *vd, void *vn, void *vm, uint32_t desc)
{
    intptr_t i, segend, opr_sz = simd_oprsz(desc), opr_sz_4 = opr_sz / 4;
    intptr_t index = simd_data(desc);
    uint32_t *d = vd;
    uint8_t *n = vn;
    uint8_t *m_indexed = (uint8_t *)vm + index * 4;

    /* Notice the special case of opr_sz == 8, from aa64/aa32 advsimd.
     * Otherwise opr_sz is a multiple of 16.
     */
    segend = MIN(4, opr_sz_4);
    i = 0;
    do {
        uint8_t m0 = m_indexed[i * 4 + 0];
        uint8_t m1 = m_indexed[i * 4 + 1];
        uint8_t m2 = m_indexed[i * 4 + 2];
        uint8_t m3 = m_indexed[i * 4 + 3];

        do {
            d[i] += n[i * 4 + 0] * m0
                  + n[i * 4 + 1] * m1
                  + n[i * 4 + 2] * m2
                  + n[i * 4 + 3] * m3;
        } while (++i < segend);
        segend = i + 4;
    } while (i < opr_sz_4);

    clear_tail(d, opr_sz, simd_maxsz(desc));
}

