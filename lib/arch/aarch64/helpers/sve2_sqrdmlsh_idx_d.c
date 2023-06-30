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

#define H8(x)   (x)

int64_t do_sqrdmlah_d(int64_t, int64_t, int64_t, bool, bool);

#define DO_ZZXZ(NAME, TYPE, H, OP) \
void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
{                                                                       \
    intptr_t oprsz = simd_oprsz(desc), segment = 16 / sizeof(TYPE);     \
    intptr_t i, j, idx = simd_data(desc);                               \
    TYPE *d = vd, *a = va, *n = vn, *m = (TYPE *)vm + H(idx);           \
    for (i = 0; i < oprsz / sizeof(TYPE); i += segment) {               \
        TYPE mm = m[i];                                                 \
        for (j = 0; j < segment; j++) {                                 \
            d[i + j] = OP(n[i + j], mm, a[i + j]);                      \
        }                                                               \
    }                                                                   \
}

#define DO_SQRDMLSH_D(N, M, A) do_sqrdmlah_d(N, M, A, true, true)

DO_ZZXZ(sve2_sqrdmlsh_idx_d, int64_t, H8, DO_SQRDMLSH_D)

