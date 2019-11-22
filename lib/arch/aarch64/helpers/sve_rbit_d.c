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

static inline uint64_t revbit64(uint64_t x)
{
    /* Assign the correct byte position.  */
    x = bswap64(x);
    /* Assign the correct nibble position.  */
    x = ((x & 0xf0f0f0f0f0f0f0f0ull) >> 4)
      | ((x & 0x0f0f0f0f0f0f0f0full) << 4);
    /* Assign the correct bit position.  */
    x = ((x & 0x8888888888888888ull) >> 3)
      | ((x & 0x4444444444444444ull) >> 1)
      | ((x & 0x2222222222222222ull) << 1)
      | ((x & 0x1111111111111111ull) << 3);
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

#define H1(x)   (x)

#define DO_ZPZ_D(NAME, TYPE, OP)                                \
void HELPER(NAME)(void *vd, void *vn, void *vg, uint32_t desc)  \
{                                                               \
    intptr_t i, opr_sz = simd_oprsz(desc) / 8;                  \
    TYPE *d = vd, *n = vn;                                      \
    uint8_t *pg = vg;                                           \
    for (i = 0; i < opr_sz; i += 1) {                           \
        if (pg[H1(i)] & 1) {                                    \
            TYPE nn = n[i];                                     \
            d[i] = OP(nn);                                      \
        }                                                       \
    }                                                           \
}

DO_ZPZ_D(sve_rbit_d, uint64_t, revbit64)

