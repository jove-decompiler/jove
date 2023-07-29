#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdbool.h>

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

static inline uint64_t do_uqrshl_d(uint64_t src, int64_t shift,
                                   bool round, uint32_t *sat)
{
    if (shift <= -(64 + round)) {
        return 0;
    } else if (shift < 0) {
        if (round) {
            src >>= -shift - 1;
            return (src >> 1) + (src & 1);
        }
        return src >> -shift;
    } else if (shift < 64) {
        uint64_t val = src << shift;
        if (!sat || val >> shift == src) {
            return val;
        }
    } else if (!sat || src == 0) {
        return 0;
    }

    *sat = 1;
    return UINT64_MAX;
}

static inline int64_t do_suqrshl_d(int64_t src, int64_t shift,
                                   bool round, uint32_t *sat)
{
    if (sat && src < 0) {
        *sat = 1;
        return 0;
    }
    return do_uqrshl_d(src, shift, round, sat);
}

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

#define do_suqrshl_d(n, m) \
   ({ uint32_t discard; do_suqrshl_d(n, m, false, &discard); })

DO_ZPZI_D(sve2_sqshlu_d, int64_t, do_suqrshl_d)

