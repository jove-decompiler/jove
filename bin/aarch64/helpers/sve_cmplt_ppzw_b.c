#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

typedef struct Int128 Int128;

struct Int128 {
#if HOST_BIG_ENDIAN
    int64_t hi;
    uint64_t lo;
#else
    uint64_t lo;
    int64_t hi;
#endif
};

static inline int clz128(Int128 a)
{
    if (a.hi) {
        return __builtin_clzll(a.hi);
    } else {
        return (a.lo) ? __builtin_clzll(a.lo) + 64 : 128;
    }
}

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

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

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

#define DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H, MASK)                     \
uint32_t HELPER(NAME)(void *vd, void *vn, void *vm, void *vg, uint32_t desc) \
{                                                                            \
    intptr_t opr_sz = simd_oprsz(desc);                                      \
    uint32_t flags = PREDTEST_INIT;                                          \
    intptr_t i = opr_sz;                                                     \
    do {                                                                     \
        uint64_t out = 0, pg;                                                \
        do {                                                                 \
            TYPEW mm = *(TYPEW *)(vm + i - 8);                               \
            do {                                                             \
                i -= sizeof(TYPE), out <<= sizeof(TYPE);                     \
                TYPE nn = *(TYPE *)(vn + H(i));                              \
                out |= nn OP mm;                                             \
            } while (i & 7);                                                 \
        } while (i & 63);                                                    \
        pg = *(uint64_t *)(vg + (i >> 3)) & MASK;                            \
        out &= pg;                                                           \
        *(uint64_t *)(vd + (i >> 3)) = out;                                  \
        flags = iter_predtest_bwd(out, pg, flags);                           \
    } while (i > 0);                                                         \
    return flags;                                                            \
}

#define DO_CMP_PPZW_B(NAME, TYPE, TYPEW, OP) \
    DO_CMP_PPZW(NAME, TYPE, TYPEW, OP, H1,   0xffffffffffffffffull)

DO_CMP_PPZW_B(sve_cmplt_ppzw_b, int8_t,   int64_t, <)

