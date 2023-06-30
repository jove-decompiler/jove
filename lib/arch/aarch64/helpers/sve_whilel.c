#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define QEMU_ALIGNED(X) __attribute__((aligned(X)))

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdint.h>

#include <stdio.h>

#include <string.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

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

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

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

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

# define ARM_MAX_VQ    16

typedef struct ARMPredicateReg {
    uint64_t p[DIV_ROUND_UP(2 * ARM_MAX_VQ, 8)] QEMU_ALIGNED(16);
} ARMPredicateReg;

extern const uint64_t pred_esz_masks[5];

FIELD(PREDDESC, OPRSZ, 0, 6)

FIELD(PREDDESC, ESZ, 6, 2)

#define HELPER(name) glue(helper_, name)

#define PREDTEST_INIT  1

static uint32_t iter_predtest_fwd(uint64_t d, uint64_t g, uint32_t flags)
{
    if (likely(g)) {
        /* Compute N from first D & G.
           Use bit 2 to signal first G bit seen.  */
        if (!(flags & 4)) {
            flags |= ((d & (g & -g)) != 0) << 31;
            flags |= 4;
        }

        /* Accumulate Z from each D & G.  */
        flags |= ((d & g) != 0) << 1;

        /* Compute C from last !(D & G).  Replace previous.  */
        flags = deposit32(flags, 0, 1, (d & pow2floor(g)) == 0);
    }
    return flags;
}

static uint32_t do_zero(ARMPredicateReg *d, intptr_t oprsz)
{
    /* It is quicker to zero the whole predicate than loop on OPRSZ.
     * The compiler should turn this into 4 64-bit integer stores.
     */
    memset(d, 0, sizeof(ARMPredicateReg));
    return PREDTEST_INIT;
}

static uint32_t predtest_ones(ARMPredicateReg *d, intptr_t oprsz,
                              uint64_t esz_mask)
{
    uint32_t flags = PREDTEST_INIT;
    intptr_t i;

    for (i = 0; i < oprsz / 8; i++) {
        flags = iter_predtest_fwd(d->p[i], esz_mask, flags);
    }
    if (oprsz & 7) {
        uint64_t mask = ~(-1ULL << (8 * (oprsz & 7)));
        flags = iter_predtest_fwd(d->p[i], esz_mask & mask, flags);
    }
    return flags;
}

uint32_t HELPER(sve_whilel)(void *vd, uint32_t count, uint32_t pred_desc)
{
    intptr_t oprsz = FIELD_EX32(pred_desc, PREDDESC, OPRSZ);
    intptr_t esz = FIELD_EX32(pred_desc, PREDDESC, ESZ);
    uint64_t esz_mask = pred_esz_masks[esz];
    ARMPredicateReg *d = vd;
    uint32_t flags;
    intptr_t i;

    /* Begin with a zero predicate register.  */
    flags = do_zero(d, oprsz);
    if (count == 0) {
        return flags;
    }

    /* Set all of the requested bits.  */
    for (i = 0; i < count / 64; ++i) {
        d->p[i] = esz_mask;
    }
    if (count & 63) {
        d->p[i] = MAKE_64BIT_MASK(0, count & 63) & esz_mask;
    }

    return predtest_ones(d, oprsz, esz_mask);
}

