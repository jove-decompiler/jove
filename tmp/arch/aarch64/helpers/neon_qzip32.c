#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define ELEM(V, N, SIZE) (((V) >> ((N) * (SIZE))) & ((1ull << (SIZE)) - 1))

void HELPER(neon_qzip32)(void *vd, void *vm)
{
    uint64_t *rd = vd, *rm = vm;
    uint64_t zd0 = rd[0], zd1 = rd[1];
    uint64_t zm0 = rm[0], zm1 = rm[1];

    uint64_t d0 = ELEM(zd0, 0, 32) | (ELEM(zm0, 0, 32) << 32);
    uint64_t d1 = ELEM(zd0, 1, 32) | (ELEM(zm0, 1, 32) << 32);
    uint64_t m0 = ELEM(zd1, 0, 32) | (ELEM(zm1, 0, 32) << 32);
    uint64_t m1 = ELEM(zd1, 1, 32) | (ELEM(zm1, 1, 32) << 32);

    rm[0] = m0;
    rm[1] = m1;
    rd[0] = d0;
    rd[1] = d1;
}

