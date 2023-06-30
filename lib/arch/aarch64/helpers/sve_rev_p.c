#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

#define bswap64(_x) __builtin_bswap64(_x)

static inline void bswap64s(uint64_t *s)
{
    *s = __builtin_bswap64(*s);
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

FIELD(PREDDESC, OPRSZ, 0, 6)

FIELD(PREDDESC, ESZ, 6, 2)

#define HELPER(name) glue(helper_, name)

#define H1(x)   (x)

static const uint64_t even_bit_esz_masks[5] = {
    0x5555555555555555ull,
    0x3333333333333333ull,
    0x0f0f0f0f0f0f0f0full,
    0x00ff00ff00ff00ffull,
    0x0000ffff0000ffffull,
};

static uint64_t reverse_bits_64(uint64_t x, int n)
{
    int i, sh;

    x = bswap64(x);
    for (i = 2, sh = 4; i >= n; i--, sh >>= 1) {
        uint64_t mask = even_bit_esz_masks[i];
        x = ((x & mask) << sh) | ((x >> sh) & mask);
    }
    return x;
}

static uint8_t reverse_bits_8(uint8_t x, int n)
{
    static const uint8_t mask[3] = { 0x55, 0x33, 0x0f };
    int i, sh;

    for (i = 2, sh = 4; i >= n; i--, sh >>= 1) {
        x = ((x & mask[i]) << sh) | ((x >> sh) & mask[i]);
    }
    return x;
}

void HELPER(sve_rev_p)(void *vd, void *vn, uint32_t pred_desc)
{
    intptr_t oprsz = FIELD_EX32(pred_desc, PREDDESC, OPRSZ);
    int esz = FIELD_EX32(pred_desc, PREDDESC, ESZ);
    intptr_t i, oprsz_2 = oprsz / 2;

    if (oprsz <= 8) {
        uint64_t l = *(uint64_t *)vn;
        l = reverse_bits_64(l << (64 - 8 * oprsz), esz);
        *(uint64_t *)vd = l;
    } else if ((oprsz & 15) == 0) {
        for (i = 0; i < oprsz_2; i += 8) {
            intptr_t ih = oprsz - 8 - i;
            uint64_t l = reverse_bits_64(*(uint64_t *)(vn + i), esz);
            uint64_t h = reverse_bits_64(*(uint64_t *)(vn + ih), esz);
            *(uint64_t *)(vd + i) = h;
            *(uint64_t *)(vd + ih) = l;
        }
    } else {
        for (i = 0; i < oprsz_2; i += 1) {
            intptr_t il = H1(i);
            intptr_t ih = H1(oprsz - 1 - i);
            uint8_t l = reverse_bits_8(*(uint8_t *)(vn + il), esz);
            uint8_t h = reverse_bits_8(*(uint8_t *)(vn + ih), esz);
            *(uint8_t *)(vd + il) = h;
            *(uint8_t *)(vd + ih) = l;
        }
    }
}

