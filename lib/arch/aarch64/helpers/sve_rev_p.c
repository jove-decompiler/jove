#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <sys/types.h>

#include <assert.h>

#include <byteswap.h>

static inline uint64_t bswap64(uint64_t x)
{
    return bswap_64(x);
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

#define SIMD_MAXSZ_SHIFT   (SIMD_OPRSZ_SHIFT + SIMD_OPRSZ_BITS)

#define SIMD_MAXSZ_BITS    5

#define SIMD_DATA_SHIFT    (SIMD_MAXSZ_SHIFT + SIMD_MAXSZ_BITS)

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
    intptr_t oprsz = extract32(pred_desc, 0, SIMD_OPRSZ_BITS) + 2;
    int esz = extract32(pred_desc, SIMD_DATA_SHIFT, 2);
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

