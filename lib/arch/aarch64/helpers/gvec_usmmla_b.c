#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_MAXSZ_SHIFT   0

#define SIMD_MAXSZ_BITS    8

#define SIMD_OPRSZ_SHIFT   (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_OPRSZ_BITS    2

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

#define H1(x)   (x)

#define H4(x)   (x)

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

static uint32_t do_usmmla_b(uint32_t sum, void *vn, void *vm)
{
    uint8_t *n = vn;
    int8_t *m = vm;

    for (intptr_t k = 0; k < 8; ++k) {
        sum += n[H1(k)] * m[H1(k)];
    }
    return sum;
}

#define DO_MMLA_B(NAME, INNER) \
    void HELPER(NAME)(void *vd, void *vn, void *vm, void *va, uint32_t desc) \
    { do_mmla_b(vd, vn, vm, va, desc, INNER); }

static void do_mmla_b(void *vd, void *vn, void *vm, void *va, uint32_t desc,
                      uint32_t (*inner_loop)(uint32_t, void *, void *))
{
    intptr_t seg, opr_sz = simd_oprsz(desc);

    for (seg = 0; seg < opr_sz; seg += 16) {
        uint32_t *d = vd + seg;
        uint32_t *a = va + seg;
        uint32_t sum0, sum1, sum2, sum3;

        /*
         * Process the entire segment at once, writing back the
         * results only after we've consumed all of the inputs.
         *
         * Key to indices by column:
         *          i   j                  i             j
         */
        sum0 = a[H4(0 + 0)];
        sum0 = inner_loop(sum0, vn + seg + 0, vm + seg + 0);
        sum1 = a[H4(0 + 1)];
        sum1 = inner_loop(sum1, vn + seg + 0, vm + seg + 8);
        sum2 = a[H4(2 + 0)];
        sum2 = inner_loop(sum2, vn + seg + 8, vm + seg + 0);
        sum3 = a[H4(2 + 1)];
        sum3 = inner_loop(sum3, vn + seg + 8, vm + seg + 8);

        d[H4(0)] = sum0;
        d[H4(1)] = sum1;
        d[H4(2)] = sum2;
        d[H4(3)] = sum3;
    }
    clear_tail(vd, opr_sz, simd_maxsz(desc));
}

DO_MMLA_B(gvec_usmmla_b, do_usmmla_b)

