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

#define H4(x)   (x)

#define DO_CMLA_FUNC(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / sizeof(TYPE);       \
    int rot = simd_data(desc);                                  \
    int sel_a = rot & 1, sel_b = sel_a ^ 1;                     \
    bool sub_r = rot == 1 || rot == 2;                          \
    bool sub_i = rot >= 2;                                      \
    TYPE *d = vd, *n = vn, *m = vm, *a = va;                    \
    for (i = 0; i < opr_sz; i += 2) {                           \
        TYPE elt1_a = n[H(i + sel_a)];                          \
        TYPE elt2_a = m[H(i + sel_a)];                          \
        TYPE elt2_b = m[H(i + sel_b)];                          \
        d[H(i)] = OP(elt1_a, elt2_a, a[H(i)], sub_r);           \
        d[H(i + 1)] = OP(elt1_a, elt2_b, a[H(i + 1)], sub_i);   \
    }                                                           \
}

#define DO_CMLA(N, M, A, S) (A + (N * M) * (S ? -1 : 1))

DO_CMLA_FUNC(sve2_cmla_zzzz_s, uint32_t, H4, DO_CMLA)

