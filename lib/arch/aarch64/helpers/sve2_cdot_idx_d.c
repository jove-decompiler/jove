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

static int64_t do_cdot_d(uint64_t n, uint64_t m, int64_t a,
                         int sel_a, int sel_b, int sub_i)
{
    for (int i = 0; i <= 1; i++) {
        int64_t elt1_r = (int16_t)(n >> (32 * i + 0));
        int64_t elt1_i = (int16_t)(n >> (32 * i + 16));
        int64_t elt2_a = (int16_t)(m >> (32 * i + 16 * sel_a));
        int64_t elt2_b = (int16_t)(m >> (32 * i + 16 * sel_b));

        a += elt1_r * elt2_a + elt1_i * elt2_b * sub_i;
    }
    return a;
}

void HELPER(sve2_cdot_idx_d)(void *vd, void *vn, void *vm,
                             void *va, uint32_t desc)
{
    int seg, opr_sz = simd_oprsz(desc);
    int rot = extract32(desc, SIMD_DATA_SHIFT, 2);
    int idx = extract32(desc, SIMD_DATA_SHIFT + 2, 2);
    int sel_a = rot & 1;
    int sel_b = sel_a ^ 1;
    int sub_i = (rot == 0 || rot == 3 ? -1 : 1);
    uint64_t *d = vd, *n = vn, *m = vm, *a = va;

    for (seg = 0; seg < opr_sz / 8; seg += 2) {
        uint64_t seg_m = m[seg + idx];
        for (int e = 0; e < 2; e++) {
            d[seg + e] = do_cdot_d(n[seg + e], seg_m, a[seg + e],
                                   sel_a, sel_b, sub_i);
        }
    }
}

