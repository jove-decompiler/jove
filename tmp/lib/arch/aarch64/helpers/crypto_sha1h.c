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

void HELPER(crypto_sha1h)(void *vd, void *vm)
{
    uint64_t *rd = vd;
    uint64_t *rm = vm;
    union CRYPTO_STATE m = { .l = { rm[0], rm[1] } };

    CR_ST_WORD(m, 0) = ror32(CR_ST_WORD(m, 0), 2);
    CR_ST_WORD(m, 1) = CR_ST_WORD(m, 2) = CR_ST_WORD(m, 3) = 0;

    rd[0] = m.l[0];
    rd[1] = m.l[1];
}

