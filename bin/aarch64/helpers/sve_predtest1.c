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

static inline uint32_t deposit32(uint32_t value, int start, int length,
                                 uint32_t fieldval)
{
    uint32_t mask;
    assert(start >= 0 && length > 0 && length <= 32 - start);
    mask = (~0U >> (32 - length)) << start;
    return (value & ~mask) | ((fieldval << start) & mask);
}

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

uint32_t HELPER(sve_predtest1)(uint64_t d, uint64_t g)
{
    return iter_predtest_fwd(d, g, PREDTEST_INIT);
}

