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

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline intptr_t simd_maxsz(uint32_t desc)
{
    return (extract32(desc, SIMD_MAXSZ_SHIFT, SIMD_MAXSZ_BITS) + 1) * 8;
}

static void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

void HELPER(gvec_uqsub_d)(void *vd, void *vq, void *vn,
                          void *vm, uint32_t desc)
{
    intptr_t i, oprsz = simd_oprsz(desc);
    uint64_t *d = vd, *n = vn, *m = vm;
    bool q = false;

    for (i = 0; i < oprsz / 8; i++) {
        uint64_t nn = n[i], mm = m[i], dd = nn - mm;
        if (nn < mm) {
            dd = 0;
            q = true;
        }
        d[i] = dd;
    }
    if (q) {
        uint32_t *qc = vq;
        qc[0] = 1;
    }
    clear_tail(d, oprsz, simd_maxsz(desc));
}

