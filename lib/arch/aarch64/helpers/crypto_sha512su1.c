#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

static inline uint64_t ror64(uint64_t word, unsigned int shift)
{
    return (word >> shift) | (word << ((64 - shift) & 63));
}

#define HELPER(name) glue(helper_, name)

static uint64_t s1_512(uint64_t x)
{
    return ror64(x, 19) ^ ror64(x, 61) ^ (x >> 6);
}

void HELPER(crypto_sha512su1)(void *vd, void *vn, void *vm)
{
    uint64_t *rd = vd;
    uint64_t *rn = vn;
    uint64_t *rm = vm;

    rd[0] += s1_512(rn[0]) + rm[0];
    rd[1] += s1_512(rn[1]) + rm[1];
}

