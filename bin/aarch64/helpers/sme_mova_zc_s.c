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

#define H1_2(x) (x)

#define H1_4(x) (x)

#define tile_vslice_offset(byteoff) ((byteoff) * sizeof(ARMVectorReg))

#define DO_MOVA_Z(NAME, TYPE, H)                                        \
void HELPER(NAME)(void *vd, void *za, void *vg, uint32_t desc)          \
{                                                                       \
    int i, oprsz = simd_oprsz(desc);                                    \
    for (i = 0; i < oprsz; ) {                                          \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));                 \
        do {                                                            \
            if (pg & 1) {                                               \
                *(TYPE *)(vd + H(i)) = *(TYPE *)(za + tile_vslice_offset(i)); \
            }                                                           \
            i += sizeof(TYPE);                                          \
            pg >>= sizeof(TYPE);                                        \
        } while (i & 15);                                               \
    }                                                                   \
}

DO_MOVA_Z(sme_mova_zc_s, uint32_t, H1_4)

