#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define ELEM(V, N, SIZE) (((V) >> ((N) * (SIZE))) & ((1ull << (SIZE)) - 1))

void HELPER(neon_qunzip8)(void *vd, void *vm)
{
    uint64_t *rd = vd, *rm = vm;
    uint64_t zd0 = rd[0], zd1 = rd[1];
    uint64_t zm0 = rm[0], zm1 = rm[1];

    uint64_t d0 = ELEM(zd0, 0, 8) | (ELEM(zd0, 2, 8) << 8)
        | (ELEM(zd0, 4, 8) << 16) | (ELEM(zd0, 6, 8) << 24)
        | (ELEM(zd1, 0, 8) << 32) | (ELEM(zd1, 2, 8) << 40)
        | (ELEM(zd1, 4, 8) << 48) | (ELEM(zd1, 6, 8) << 56);
    uint64_t d1 = ELEM(zm0, 0, 8) | (ELEM(zm0, 2, 8) << 8)
        | (ELEM(zm0, 4, 8) << 16) | (ELEM(zm0, 6, 8) << 24)
        | (ELEM(zm1, 0, 8) << 32) | (ELEM(zm1, 2, 8) << 40)
        | (ELEM(zm1, 4, 8) << 48) | (ELEM(zm1, 6, 8) << 56);
    uint64_t m0 = ELEM(zd0, 1, 8) | (ELEM(zd0, 3, 8) << 8)
        | (ELEM(zd0, 5, 8) << 16) | (ELEM(zd0, 7, 8) << 24)
        | (ELEM(zd1, 1, 8) << 32) | (ELEM(zd1, 3, 8) << 40)
        | (ELEM(zd1, 5, 8) << 48) | (ELEM(zd1, 7, 8) << 56);
    uint64_t m1 = ELEM(zm0, 1, 8) | (ELEM(zm0, 3, 8) << 8)
        | (ELEM(zm0, 5, 8) << 16) | (ELEM(zm0, 7, 8) << 24)
        | (ELEM(zm1, 1, 8) << 32) | (ELEM(zm1, 3, 8) << 40)
        | (ELEM(zm1, 5, 8) << 48) | (ELEM(zm1, 7, 8) << 56);

    rm[0] = m0;
    rm[1] = m1;
    rd[0] = d0;
    rd[1] = d1;
}

