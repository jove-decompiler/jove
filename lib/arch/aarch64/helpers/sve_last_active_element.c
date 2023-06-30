#define HOST_BIG_ENDIAN (__BYTE_ORDER__ == __ORDER_BIG_ENDIAN__)

#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

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

#define MAKE_64BIT_MASK(shift, length) \
    (((~0ULL) >> (64 - (length))) << (shift))

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define FIELD(reg, field, shift, length)                                  \
    enum { R_ ## reg ## _ ## field ## _SHIFT = (shift)};                  \
    enum { R_ ## reg ## _ ## field ## _LENGTH = (length)};                \
    enum { R_ ## reg ## _ ## field ## _MASK =                             \
                                        MAKE_64BIT_MASK(shift, length)};

#define FIELD_EX32(storage, reg, field)                                   \
    extract32((storage), R_ ## reg ## _ ## field ## _SHIFT,               \
              R_ ## reg ## _ ## field ## _LENGTH)

extern const uint64_t pred_esz_masks[5];

FIELD(PREDDESC, OPRSZ, 0, 6)

FIELD(PREDDESC, ESZ, 6, 2)

#define HELPER(name) glue(helper_, name)

static intptr_t last_active_element(uint64_t *g, intptr_t words, intptr_t esz)
{
    uint64_t mask = pred_esz_masks[esz];
    intptr_t i = words;

    do {
        uint64_t this_g = g[--i] & mask;
        if (this_g) {
            return i * 64 + (63 - clz64(this_g));
        }
    } while (i > 0);
    return (intptr_t)-1 << esz;
}

int32_t HELPER(sve_last_active_element)(void *vg, uint32_t pred_desc)
{
    intptr_t words = DIV_ROUND_UP(FIELD_EX32(pred_desc, PREDDESC, OPRSZ), 8);
    intptr_t esz = FIELD_EX32(pred_desc, PREDDESC, ESZ);

    return last_active_element(vg, words, esz);
}

