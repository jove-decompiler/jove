#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stddef.h>

#include <stdint.h>

#include <string.h>

#include <assert.h>

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

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

#define HELPER(name) glue(helper_, name)

#define H1(x)   (x)

#define H4(x)   (x)

void HELPER(sve2_histcnt_s)(void *vd, void *vn, void *vm, void *vg,
                            uint32_t desc)
{
    ARMVectorReg scratch;
    intptr_t i, j;
    intptr_t opr_sz = simd_oprsz(desc);
    uint32_t *d = vd, *n = vn, *m = vm;
    uint8_t *pg = vg;

    if (d == n) {
        n = memcpy(&scratch, n, opr_sz);
        if (d == m) {
            m = n;
        }
    } else if (d == m) {
        m = memcpy(&scratch, m, opr_sz);
    }

    for (i = 0; i < opr_sz; i += 4) {
        uint64_t count = 0;
        uint8_t pred;

        pred = pg[H1(i >> 3)] >> (i & 7);
        if (pred & 1) {
            uint32_t nn = n[H4(i >> 2)];

            for (j = 0; j <= i; j += 4) {
                pred = pg[H1(j >> 3)] >> (j & 7);
                if ((pred & 1) && nn == m[H4(j >> 2)]) {
                    ++count;
                }
            }
        }
        d[H4(i >> 2)] = count;
    }
}

