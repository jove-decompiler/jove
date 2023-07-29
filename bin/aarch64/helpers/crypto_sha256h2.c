#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
    return (word >> (shift & 31)) | (word << (-shift & 31));
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

#define CR_ST_WORD(state, i)   ((state).words[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

static void clear_tail_16(void *vd, uint32_t desc)
{
    int opr_sz = simd_oprsz(desc);
    int max_sz = simd_maxsz(desc);

    assert(opr_sz == 16);
    clear_tail(vd, opr_sz, max_sz);
}

static uint32_t cho(uint32_t x, uint32_t y, uint32_t z)
{
    return (x & (y ^ z)) ^ z;
}

static uint32_t S1(uint32_t x)
{
    return ror32(x, 6) ^ ror32(x, 11) ^ ror32(x, 25);
}

void HELPER(crypto_sha256h2)(void *vd, void *vn, void *vm, uint32_t desc)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;
    union CRYPTO_STATE d = { .l = { rd[0], rd[1] } };
    union CRYPTO_STATE n = { .l = { rn[0], rn[1] } };
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };
    int i;

    for (i = 0; i < 4; i++) {
        uint32_t t = cho(CR_ST_WORD(d, 0), CR_ST_WORD(d, 1), CR_ST_WORD(d, 2))
                     + CR_ST_WORD(d, 3) + S1(CR_ST_WORD(d, 0))
                     + CR_ST_WORD(m, i);

        CR_ST_WORD(d, 3) = CR_ST_WORD(d, 2);
        CR_ST_WORD(d, 2) = CR_ST_WORD(d, 1);
        CR_ST_WORD(d, 1) = CR_ST_WORD(d, 0);
        CR_ST_WORD(d, 0) = CR_ST_WORD(n, 3 - i) + t;
    }

    rd[0] = d.l[0];
    rd[1] = d.l[1];

    clear_tail_16(vd, desc);
}

