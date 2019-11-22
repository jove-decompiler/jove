#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stddef.h>

#include <stdint.h>

#include <string.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

static inline uint64_t extract64(uint64_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 64 - start);
    return (value >> start) & (~0ULL >> (64 - length));
}

# define ARM_MAX_VQ    16

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define H1(x)   (x)

#define H2(x)   (x)

#define H4(x)   (x)

static const uint64_t even_bit_esz_masks[5] = {
    0x5555555555555555ull,
    0x3333333333333333ull,
    0x0f0f0f0f0f0f0f0full,
    0x00ff00ff00ff00ffull,
    0x0000ffff0000ffffull,
};

static uint64_t expand_bits(uint64_t x, int n)
{
    int i;

    x &= 0xffffffffu;
    for (i = 4; i >= n; i--) {
        int sh = 1 << i;
        x = ((x << sh) | x) & even_bit_esz_masks[i];
    }
    return x;
}

void HELPER(sve_punpk_p)(void *vd, void *vn, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    intptr_t high = extract32(pred_desc, SIMD_DATA_SHIFT + 2, 1);
    uint64_t *d = vd;
    intptr_t i;

    if (oprsz <= 8) {
        uint64_t nn = *(uint64_t *)vn;
        int half = 4 * oprsz;

        nn = extract64(nn, high * half, half);
        nn = expand_bits(nn, 0);
        d[0] = nn;
    } else {
        ARMPredicateReg tmp_n;

        /* We produce output faster than we consume input.
           Therefore we must be mindful of possible overlap.  */
        if ((vn - vd) < (uintptr_t)oprsz) {
            vn = memcpy(&tmp_n, vn, oprsz);
        }
        if (high) {
            high = oprsz >> 1;
        }

        if ((high & 3) == 0) {
            uint32_t *n = vn;
            high >>= 2;

            for (i = 0; i < DIV_ROUND_UP(oprsz, 8); i++) {
                uint64_t nn = n[H4(high + i)];
                d[i] = expand_bits(nn, 0);
            }
        } else {
            uint16_t *d16 = vd;
            uint8_t *n = vn;

            for (i = 0; i < oprsz / 2; i++) {
                uint16_t nn = n[H1(high + i)];
                d16[H2(i)] = expand_bits(nn, 0);
            }
        }
    }
}

