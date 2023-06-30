#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <assert.h>

static inline uint32_t rol32(uint32_t word, unsigned int shift)
{
    return (word << (shift & 31)) | (word >> (-shift & 31));
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

extern const uint8_t sm4_sbox[256];

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

static void do_crypto_sm4ekey(uint64_t *rd, uint64_t *rn, uint64_t *rm)
{
    union CRYPTO_STATE d;
    union CRYPTO_STATE n = { .l = { rn[0], rn[1] } };
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };
    uint32_t t, i;

    d = n;
    for (i = 0; i < 4; i++) {
        t = CR_ST_WORD(d, (i + 1) % 4) ^
            CR_ST_WORD(d, (i + 2) % 4) ^
            CR_ST_WORD(d, (i + 3) % 4) ^
            CR_ST_WORD(m, i);

        t = sm4_sbox[t & 0xff] |
            sm4_sbox[(t >> 8) & 0xff] << 8 |
            sm4_sbox[(t >> 16) & 0xff] << 16 |
            sm4_sbox[(t >> 24) & 0xff] << 24;

        CR_ST_WORD(d, i) ^= t ^ rol32(t, 13) ^ rol32(t, 23);
    }

    rd[0] = d.l[0];
    rd[1] = d.l[1];
}

void HELPER(crypto_sm4ekey)(void *vd, void *vn, void* vm, uint32_t desc)
{
    intptr_t i, opr_sz = simd_oprsz(desc);

    for (i = 0; i < opr_sz; i += 16) {
        do_crypto_sm4ekey(vd + i, vn + i, vm + i);
    }
    clear_tail(vd, opr_sz, simd_maxsz(desc));
}

