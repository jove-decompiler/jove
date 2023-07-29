#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

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

#define H1_2(x) (x)

#define H1_4(x) (x)

#define DO_MUL(N, M)  (N * M)

#define DO_ZZX(NAME, TYPEW, TYPEN, HW, HN, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, uint32_t desc)            \
{                                                                         \
    intptr_t i, j, oprsz = simd_oprsz(desc);                              \
    intptr_t sel = extract32(desc, SIMD_DATA_SHIFT, 1) * sizeof(TYPEN);   \
    intptr_t idx = extract32(desc, SIMD_DATA_SHIFT + 1, 3) * sizeof(TYPEN); \
    for (i = 0; i < oprsz; i += 16) {                                     \
        TYPEW mm = *(TYPEN *)(vm + HN(i + idx));                          \
        for (j = 0; j < 16; j += sizeof(TYPEW)) {                         \
            TYPEW nn = *(TYPEN *)(vn + HN(i + j + sel));                  \
            *(TYPEW *)(vd + HW(i + j)) = OP(nn, mm);                      \
        }                                                                 \
    }                                                                     \
}

DO_ZZX(sve2_smull_idx_s, int32_t, int16_t, H1_4, H1_2, DO_MUL)

