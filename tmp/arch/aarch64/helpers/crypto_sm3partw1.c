#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline uint32_t ror32(uint32_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((32 - shift) & 31));
}

#define HELPER(name) glue(helper_, name)

#define CR_ST_WORD(state, i)   (state.words[i])

union CRYPTO_STATE {
    uint8_t    bytes[16];
    uint32_t   words[4];
    uint64_t   l[2];
};

void HELPER(crypto_sm3partw1)(void *vd, void *vn, void *vm)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;
    union CRYPTO_STATE d = { .l = { rd[0], rd[1] } };
    union CRYPTO_STATE n = { .l = { rn[0], rn[1] } };
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };
    uint32_t t;

    t = CR_ST_WORD(d, 0) ^ CR_ST_WORD(n, 0) ^ ror32(CR_ST_WORD(m, 1), 17);
    CR_ST_WORD(d, 0) = t ^ ror32(t, 17) ^ ror32(t, 9);

    t = CR_ST_WORD(d, 1) ^ CR_ST_WORD(n, 1) ^ ror32(CR_ST_WORD(m, 2), 17);
    CR_ST_WORD(d, 1) = t ^ ror32(t, 17) ^ ror32(t, 9);

    t = CR_ST_WORD(d, 2) ^ CR_ST_WORD(n, 2) ^ ror32(CR_ST_WORD(m, 3), 17);
    CR_ST_WORD(d, 2) = t ^ ror32(t, 17) ^ ror32(t, 9);

    t = CR_ST_WORD(d, 3) ^ CR_ST_WORD(n, 3) ^ ror32(CR_ST_WORD(d, 0), 17);
    CR_ST_WORD(d, 3) = t ^ ror32(t, 17) ^ ror32(t, 9);

    rd[0] = d.l[0];
    rd[1] = d.l[1];
}

