#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

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

#define tile_vslice_index(i) ((i) * sizeof(ARMVectorReg))

void HELPER(sme_addva_d)(void *vzda, void *vzn, void *vpn,
                         void *vpm, uint32_t desc)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / 8;
    uint8_t *pn = vpn, *pm = vpm;
    uint64_t *zda = vzda, *zn = vzn;

    for (row = 0; row < oprsz; ++row) {
        if (pn[H1(row)] & 1) {
            uint64_t zn_row = zn[row];
            for (col = 0; col < oprsz; ++col) {
                if (pm[H1(col)] & 1) {
                    zda[tile_vslice_index(row) + col] += zn_row;
                }
            }
        }
    }
}

