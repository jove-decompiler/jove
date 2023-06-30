#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define DIV_ROUND_UP(n, d) (((n) + (d) - 1) / (d))

static inline int ctpop64(uint64_t val)
{
    return __builtin_popcountll(val);
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

uint64_t HELPER(sve_cntp)(void *vn, void *vg, uint32_t pred_desc)
{
    intptr_t words = DIV_ROUND_UP(FIELD_EX32(pred_desc, PREDDESC, OPRSZ), 8);
    intptr_t esz = FIELD_EX32(pred_desc, PREDDESC, ESZ);
    uint64_t *n = vn, *g = vg, sum = 0, mask = pred_esz_masks[esz];
    intptr_t i;

    for (i = 0; i < words; ++i) {
        uint64_t t = n[i] & g[i] & mask;
        sum += ctpop64(t);
    }
    return sum;
}

