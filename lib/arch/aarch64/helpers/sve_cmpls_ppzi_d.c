#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

static inline int clz64(uint64_t val)
{
    return val ? __builtin_clzll(val) : 64;
}

static inline uint64_t pow2floor(uint64_t value)
{
    if (!value) {
        /* Avoid undefined shift by 64 */
        return 0;
    }
    return 0x8000000000000000ull >> clz64(value);
}

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

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

#define SIMD_DATA_BITS     (32 - SIMD_DATA_SHIFT)

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

static inline int32_t simd_data(uint32_t desc)
{
    return sextract32(desc, SIMD_DATA_SHIFT, SIMD_DATA_BITS);
}

#define PREDTEST_INIT  1

static uint32_t iter_predtest_bwd(uint64_t d, uint64_t g, uint32_t flags)
{
    if (likely(g)) {
        /* Compute C from first (i.e last) !(D & G).
           Use bit 2 to signal first G bit seen.  */
        if (!(flags & 4)) {
            flags += 4 - 1; /* add bit 2, subtract C from PREDTEST_INIT */
            flags |= (d & pow2floor(g)) == 0;
        }

        /* Accumulate Z from each D & G.  */
        flags |= ((d & g) != 0) << 1;

        /* Compute N from last (i.e first) D & G.  Replace previous.  */
        flags = deposit32(flags, 31, 1, (d & (g & -g)) != 0);
    }
    return flags;
}

#define DO_CMP_PPZI(NAME, TYPE, OP, H, MASK)                         \
uint32_t HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)   \
{                                                                    \
    intptr_t opr_sz = simd_oprsz(desc);                              \
    uint32_t flags = PREDTEST_INIT;                                  \
    TYPE mm = simd_data(desc);                                       \
    intptr_t i = opr_sz;                                             \
    do {                                                             \
        uint64_t out = 0, pg;                                        \
        do {                                                         \
            i -= sizeof(TYPE), out <<= sizeof(TYPE);                 \
            TYPE nn = *(TYPE *)(vn + H(i));                          \
            out |= nn OP mm;                                         \
        } while (i & 63);                                            \
        pg = *(uint64_t *)(vg + (i >> 3)) & MASK;                    \
        out &= pg;                                                   \
        *(uint64_t *)(vd + (i >> 3)) = out;                          \
        flags = iter_predtest_bwd(out, pg, flags);                   \
    } while (i > 0);                                                 \
    return flags;                                                    \
}

#define DO_CMP_PPZI_D(NAME, TYPE, OP) \
    DO_CMP_PPZI(NAME, TYPE, OP,     , 0x0101010101010101ull)

DO_CMP_PPZI_D(sve_cmpls_ppzi_d, uint64_t, <=)

