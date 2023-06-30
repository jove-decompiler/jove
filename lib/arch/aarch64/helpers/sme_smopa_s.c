#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

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

#define H1(x)   (x)

extern const uint64_t expand_pred_b_data[256];

static inline uint64_t expand_pred_b(uint8_t byte)
{
    return expand_pred_b_data[byte];
}

#define tile_vslice_index(i) ((i) * sizeof(ARMVectorReg))

typedef uint64_t IMOPFn(uint64_t, uint64_t, uint64_t, uint8_t, bool);

#define DEF_IMOP_32(NAME, NTYPE, MTYPE) \
static uint64_t NAME(uint64_t n, uint64_t m, uint64_t a, uint8_t p, bool neg) \
{                                                                           \
    uint32_t sum0 = 0, sum1 = 0;                                            \
    /* Apply P to N as a mask, making the inactive elements 0. */           \
    n &= expand_pred_b(p);                                                  \
    sum0 += (NTYPE)(n >> 0) * (MTYPE)(m >> 0);                              \
    sum0 += (NTYPE)(n >> 8) * (MTYPE)(m >> 8);                              \
    sum0 += (NTYPE)(n >> 16) * (MTYPE)(m >> 16);                            \
    sum0 += (NTYPE)(n >> 24) * (MTYPE)(m >> 24);                            \
    sum1 += (NTYPE)(n >> 32) * (MTYPE)(m >> 32);                            \
    sum1 += (NTYPE)(n >> 40) * (MTYPE)(m >> 40);                            \
    sum1 += (NTYPE)(n >> 48) * (MTYPE)(m >> 48);                            \
    sum1 += (NTYPE)(n >> 56) * (MTYPE)(m >> 56);                            \
    if (neg) {                                                              \
        sum0 = (uint32_t)a - sum0, sum1 = (uint32_t)(a >> 32) - sum1;       \
    } else {                                                                \
        sum0 = (uint32_t)a + sum0, sum1 = (uint32_t)(a >> 32) + sum1;       \
    }                                                                       \
    return ((uint64_t)sum1 << 32) | sum0;                                   \
}

DEF_IMOP_32(smopa_s, int8_t, int8_t)

static inline void do_imopa(uint64_t *za, uint64_t *zn, uint64_t *zm,
                            uint8_t *pn, uint8_t *pm,
                            uint32_t desc, IMOPFn *fn)
{
    intptr_t row, col, oprsz = simd_oprsz(desc) / 8;
    bool neg = simd_data(desc);

    for (row = 0; row < oprsz; ++row) {
        uint8_t pa = pn[H1(row)];
        uint64_t *za_row = &za[tile_vslice_index(row)];
        uint64_t n = zn[row];

        for (col = 0; col < oprsz; ++col) {
            uint8_t pb = pm[H1(col)];
            uint64_t *a = &za_row[col];

            *a = fn(n, zm[col], *a, pa & pb, neg);
        }
    }
}

#define DEF_IMOPH(NAME) \
    void HELPER(sme_##NAME)(void *vza, void *vzn, void *vzm, void *vpn,      \
                            void *vpm, uint32_t desc)                        \
    { do_imopa(vza, vzn, vzm, vpn, vpm, desc, NAME); }

DEF_IMOPH(smopa_s)

