#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
    return (word >> (shift & 63)) | (word << (-shift & 63));
}

static inline uint32_t extract32(uint32_t value, int start, int length)
{
    assert(start >= 0 && length > 0 && length <= 32 - start);
    return (value >> start) & (~0U >> (32 - length));
}

#define HELPER(name) glue(helper_, name)

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

static inline void clear_tail(void *vd, uintptr_t opr_sz, uintptr_t max_sz)
{
    uint64_t *d = vd + opr_sz;
    uintptr_t i;

    for (i = opr_sz; i < max_sz; i += 8) {
        *d++ = 0;
    }
}

static void clear_tail_16(void *vd, uint32_t desc)
{
    int opr_sz = simd_oprsz(desc);
    int max_sz = simd_maxsz(desc);

    assert(opr_sz == 16);
    clear_tail(vd, opr_sz, max_sz);
}

static uint64_t cho512(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & (y ^ z)) ^ z;
}

static uint64_t S1_512(uint64_t x)
{
    return ror64(x, 14) ^ ror64(x, 18) ^ ror64(x, 41);
}

void HELPER(crypto_sha512h)(void *vd, void *vn, void *vm, uint32_t desc)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;
    uint64_t d0 = rd[0];
    uint64_t d1 = rd[1];

    d1 += S1_512(rm[1]) + cho512(rm[1], rn[0], rn[1]);
    d0 += S1_512(d1 + rm[0]) + cho512(d1 + rm[0], rm[1], rn[0]);

    rd[0] = d0;
    rd[1] = d1;

    clear_tail_16(vd, desc);
}

