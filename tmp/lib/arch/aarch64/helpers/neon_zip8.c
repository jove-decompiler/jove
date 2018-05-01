#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define ELEM(V, N, SIZE) (((V) >> ((N) * (SIZE))) & ((1ull << (SIZE)) - 1))

void HELPER(neon_zip8)(void *vd, void *vm)
{
    uint64_t *rd = vd, *rm = vm;
    uint64_t zd = rd[0], zm = rm[0];

    uint64_t d0 = ELEM(zd, 0, 8) | (ELEM(zm, 0, 8) << 8)
        | (ELEM(zd, 1, 8) << 16) | (ELEM(zm, 1, 8) << 24)
        | (ELEM(zd, 2, 8) << 32) | (ELEM(zm, 2, 8) << 40)
        | (ELEM(zd, 3, 8) << 48) | (ELEM(zm, 3, 8) << 56);
    uint64_t m0 = ELEM(zd, 4, 8) | (ELEM(zm, 4, 8) << 8)
        | (ELEM(zd, 5, 8) << 16) | (ELEM(zm, 5, 8) << 24)
        | (ELEM(zd, 6, 8) << 32) | (ELEM(zm, 6, 8) << 40)
        | (ELEM(zd, 7, 8) << 48) | (ELEM(zm, 7, 8) << 56);

    rm[0] = m0;
    rd[0] = d0;
}

