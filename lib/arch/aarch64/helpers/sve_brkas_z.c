#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#define likely(x)   __builtin_expect(!!(x), 1)

#include <stddef.h>

#include <stdbool.h>

#include <stdint.h>

#include <stdio.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

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

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_BITS    5

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

static bool compute_brk(uint64_t *retb, uint64_t n, uint64_t g,
                        bool brk, bool after)
{
    uint64_t b;

    if (brk) {
        b = 0;
    } else if ((g & n) == 0) {
        /* For all G, no N are set; break not found.  */
        b = g;
    } else {
        /* Break somewhere in N.  Locate it.  */
        b = g & n;            /* guard true, pred true */
        b = b & -b;           /* first such */
        if (after) {
            b = b | (b - 1);  /* break after same */
        } else {
            b = b - 1;        /* break before same */
        }
        brk = true;
    }

    *retb = b;
    return brk;
}

static uint32_t compute_brks_z(uint64_t *d, uint64_t *n, uint64_t *g,
                               intptr_t oprsz, bool after)
{
    uint32_t flags = PREDTEST_INIT;
    bool brk = false;
    intptr_t i;

    for (i = 0; i < DIV_ROUND_UP(oprsz, 8); ++i) {
        uint64_t this_b, this_d, this_g = g[i];

        brk = compute_brk(&this_b, n[i], this_g, brk, after);
        d[i] = this_d = this_b & this_g;
        flags = iter_predtest_fwd(this_d, this_g, flags);
    }
    return flags;
}

uint32_t HELPER(sve_brkas_z)(void *vd, void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    return compute_brks_z(vd, vn, vg, oprsz, true);
}

