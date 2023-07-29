#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define MIN(a, b)                                       \
    ({                                                  \
        typeof(1 ? (a) : (b)) _a = (a), _b = (b);       \
        _a < _b ? _a : _b;                              \
    })

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

#define H4(x)   (x)

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

#define DO_DOT_IDX(NAME, TYPED, TYPEN, TYPEM, HD) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc)  \
{                                                                         \
    intptr_t i = 0, opr_sz = simd_oprsz(desc);                            \
    intptr_t opr_sz_n = opr_sz / sizeof(TYPED);                           \
    intptr_t segend = MIN(16 / sizeof(TYPED), opr_sz_n);                  \
    intptr_t index = simd_data(desc);                                     \
    TYPED *d = vd, *a = va;                                               \
    TYPEN *n = vn;                                                        \
    TYPEM *m_indexed = (TYPEM *)vm + HD(index) * 4;                       \
    do {                                                                  \
        TYPED m0 = m_indexed[i * 4 + 0];                                  \
        TYPED m1 = m_indexed[i * 4 + 1];                                  \
        TYPED m2 = m_indexed[i * 4 + 2];                                  \
        TYPED m3 = m_indexed[i * 4 + 3];                                  \
        do {                                                              \
            d[i] = (a[i] +                                                \
                    n[i * 4 + 0] * m0 +                                   \
                    n[i * 4 + 1] * m1 +                                   \
                    n[i * 4 + 2] * m2 +                                   \
                    n[i * 4 + 3] * m3);                                   \
        } while (++i < segend);                                           \
        segend = i + 4;                                                   \
    } while (i < opr_sz_n);                                               \
    clear_tail(d, opr_sz, simd_maxsz(desc));                              \
}

DO_DOT_IDX(gvec_sudot_idx_b, int32_t, int8_t, uint8_t, H4)

