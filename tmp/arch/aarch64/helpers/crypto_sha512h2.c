#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((64 - shift) & 63));
}

#define HELPER(name) glue(helper_, name)

static uint64_t maj512(uint64_t x, uint64_t y, uint64_t z)
{
    return (x & y) | ((x | y) & z);
}

static uint64_t S0_512(uint64_t x)
{
    return ror64(x, 28) ^ ror64(x, 34) ^ ror64(x, 39);
}

void HELPER(crypto_sha512h2)(void *vd, void *vn, void *vm)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;
    uint64_t d0 = rd[0];
    uint64_t d1 = rd[1];

    d1 += S0_512(rm[0]) + maj512(rn[0], rm[1], rm[0]);
    d0 += S0_512(d1) + maj512(d1, rm[0], rm[1]);

    rd[0] = d0;
    rd[1] = d1;
}

