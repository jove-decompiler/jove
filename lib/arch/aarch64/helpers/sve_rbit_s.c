#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <sys/types.h>

#include <assert.h>

#include <byteswap.h>

static inline uint32_t bswap32(uint32_t x)
{
    return bswap_32(x);
}

static inline uint32_t revbit32(uint32_t x)
{
    /* Assign the correct byte position.  */
    x = bswap32(x);
    /* Assign the correct nibble position.  */
    x = ((x & 0xf0f0f0f0u) >> 4)
      | ((x & 0x0f0f0f0fu) << 4);
    /* Assign the correct bit position.  */
    x = ((x & 0x88888888u) >> 3)
      | ((x & 0x44444444u) >> 1)
      | ((x & 0x22222222u) << 1)
      | ((x & 0x11111111u) << 3);
    return x;
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

#define SIMD_OPRSZ_SHIFT   0

#define SIMD_OPRSZ_BITS    5

static inline intptr_t simd_oprsz(uint32_t desc)
{
    return (extract32(desc, SIMD_OPRSZ_SHIFT, SIMD_OPRSZ_BITS) + 1) * 8;
}

#define H1_2(x) (x)

#define H1_4(x) (x)

#define DO_ZPZ(NAME, TYPE, H, OP)                               \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc);                      \
    for (i = 0; i < opr_sz; ) {                                 \
        uint16_t pg = *(uint16_t *)(vg + H1_2(i >> 3));         \
        do {                                                    \
            if (pg & 1) {                                       \
                TYPE nn = *(TYPE *)(vn + H(i));                 \
                *(TYPE *)(vd + H(i)) = OP(nn);                  \
            }                                                   \
            i += sizeof(TYPE), pg >>= sizeof(TYPE);             \
        } while (i & 15);                                       \
    }                                                           \
}

DO_ZPZ(sve_rbit_s, uint32_t, H1_4, revbit32)

