#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define ELEM(V, N, SIZE) (((V) >> ((N) * (SIZE))) & ((1ull << (SIZE)) - 1))

void HELPER(neon_unzip16)(void *vd, void *vm)
{
    uint64_t *rd = vd, *rm = vm;
    uint64_t zd = rd[0], zm = rm[0];

    uint64_t d0 = ELEM(zd, 0, 16) | (ELEM(zd, 2, 16) << 16)
        | (ELEM(zm, 0, 16) << 32) | (ELEM(zm, 2, 16) << 48);
    uint64_t m0 = ELEM(zd, 1, 16) | (ELEM(zd, 3, 16) << 16)
        | (ELEM(zm, 1, 16) << 32) | (ELEM(zm, 3, 16) << 48);

    rm[0] = m0;
    rd[0] = d0;
}

