#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((64 - shift) & 63));
}

#define HELPER(name) glue(helper_, name)

static uint64_t s0_512(uint64_t x)
{
    return ror64(x, 1) ^ ror64(x, 8) ^ (x >> 7);
}

void HELPER(crypto_sha512su0)(void *vd, void *vn)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t d0 = rd[0];
    uint64_t d1 = rd[1];

    d0 += s0_512(rd[1]);
    d1 += s0_512(rn[0]);

    rd[0] = d0;
    rd[1] = d1;
}

