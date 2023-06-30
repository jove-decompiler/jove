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

#define HELPER(name) glue(helper_, name)

#define H1(x)   (x)

#define DO_ZPZI_D(NAME, TYPE, OP)                               \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn;                                      \
    TYPE imm = simd_data(desc);                                 \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 1) {                           \
        if (pg[H1(i)] & 1) {                                    \
            TYPE nn = n[i];                                     \
            d[i] = OP(nn, imm);                                 \
        }                                                       \
    }                                                           \
}

#define DO_ASRD(N, M) ((N + (N < 0 ? ((__typeof(N))1 << M) - 1 : 0)) >> M)

DO_ZPZI_D(sve_asrd_d, int64_t, DO_ASRD)

