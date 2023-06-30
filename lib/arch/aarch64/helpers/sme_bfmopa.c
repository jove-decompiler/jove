#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

typedef uint32_t float32;

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

# define ARM_MAX_VQ    16

typedef struct ARMVectorReg {
    uint64_t d[2 * ARM_MAX_VQ] QEMU_ALIGNED(16);
} ARMVectorReg;

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

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define HELPER(name) glue(helper_, name)

#define H1_4(x) (x)

#define H2(x)   (x)

float32 bfdotadd(float32 sum, uint32_t e1, uint32_t e2);

#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

static inline uint32_t f16mop_adj_pair(uint32_t pair, uint32_t pg, uint32_t neg)
{
    /*
     * The pseudocode uses a conditional negate after the conditional zero.
     * It is simpler here to unconditionally negate before conditional zero.
     */
    pair ^= neg;
    if (!(pg & 1)) {
        pair &= 0xffff0000u;
    }
    if (!(pg & 4)) {
        pair &= 0x0000ffffu;
    }
    return pair;
}

void HELPER(sme_bfmopa)(void *vza, void *vzn, void *vzm, void *vpn,
                        void *vpm, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_maxsz(desc);
    uint32_t neg = simd_data(desc) * 0x80008000u;
    uint16_t *pn = vpn, *pm = vpm;

    for (row = 0; row < oprsz; ) {
        uint16_t prow = pn[H2(row >> 4)];
        do {
            void *vza_row = vza + tile_vslice_offset(row);
            uint32_t n = *(uint32_t *)(vzn + H1_4(row));

            n = f16mop_adj_pair(n, prow, neg);

            for (col = 0; col < oprsz; ) {
                uint16_t pcol = pm[H2(col >> 4)];
                do {
                    if (prow & pcol & 0b0101) {
                        uint32_t *a = vza_row + H1_4(col);
                        uint32_t m = *(uint32_t *)(vzm + H1_4(col));

                        m = f16mop_adj_pair(m, pcol, 0);
                        *a = bfdotadd(*a, n, m);

                        col += 4;
                        pcol >>= 4;
                    }
                } while (col & 15);
            }
            row += 4;
            prow >>= 4;
        } while (row & 15);
    }
}

