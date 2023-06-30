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

#define H2(x)   (x)

#define DO_CMLA(N, M, A, S) (A + (N * M) * (S ? -1 : 1))

#define DO_CMLA_IDX_FUNC(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc)    \
{                                                                           \
    intptr_t i, j, oprsz = simd_oprsz(desc);                                \
    int rot = extract32(desc, SIMD_DATA_SHIFT, 2);                          \
    int idx = extract32(desc, SIMD_DATA_SHIFT + 2, 2) * 2;                  \
    int sel_a = rot & 1, sel_b = sel_a ^ 1;                                 \
    bool sub_r = rot == 1 || rot == 2;                                      \
    bool sub_i = rot >= 2;                                                  \
    TYPE *d = vd, *n = vn, *m = vm, *a = va;                                \
    for (i = 0; i < oprsz / sizeof(TYPE); i += 16 / sizeof(TYPE)) {         \
        TYPE elt2_a = m[H(i + idx + sel_a)];                                \
        TYPE elt2_b = m[H(i + idx + sel_b)];                                \
        for (j = 0; j < 16 / sizeof(TYPE); j += 2) {                        \
            TYPE elt1_a = n[H(i + j + sel_a)];                              \
            d[H2(i + j)] = OP(elt1_a, elt2_a, a[H(i + j)], sub_r);          \
            d[H2(i + j + 1)] = OP(elt1_a, elt2_b, a[H(i + j + 1)], sub_i);  \
        }                                                                   \
    }                                                                       \
}

DO_CMLA_IDX_FUNC(sve2_cmla_idx_h, int16_t, H2, DO_CMLA)

