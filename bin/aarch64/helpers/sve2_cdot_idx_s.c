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

#define H4(x)   (x)

static int32_t do_cdot_s(uint32_t n, uint32_t m, int32_t a,
                         int sel_a, int sel_b, int sub_i)
{
    for (int i = 0; i <= 1; i++) {
        int32_t elt1_r = (int8_t)(n >> (16 * i));
        int32_t elt1_i = (int8_t)(n >> (16 * i + 8));
        int32_t elt2_a = (int8_t)(m >> (16 * i + 8 * sel_a));
        int32_t elt2_b = (int8_t)(m >> (16 * i + 8 * sel_b));

        a += elt1_r * elt2_a + elt1_i * elt2_b * sub_i;
    }
    return a;
}

void HELPER(sve2_cdot_idx_s)(void *vd, void *vn, void *vm,
                             void *va, uint32_t desc)
{
    int opr_sz = simd_oprsz(desc);
    int rot = extract32(desc, SIMD_DATA_SHIFT, 2);
    int idx = H4(extract32(desc, SIMD_DATA_SHIFT + 2, 2));
    int sel_a = rot & 1;
    int sel_b = sel_a ^ 1;
    int sub_i = (rot == 0 || rot == 3 ? -1 : 1);
    uint32_t *d = vd, *n = vn, *m = vm, *a = va;

    for (int seg = 0; seg < opr_sz / 4; seg += 4) {
        uint32_t seg_m = m[seg + idx];
        for (int e = 0; e < 4; e++) {
            d[seg + e] = do_cdot_s(n[seg + e], seg_m, a[seg + e],
                                   sel_a, sel_b, sub_i);
        }
    }
}

