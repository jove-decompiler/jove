#include <stdint.h>

static inline int ctz64(uint64_t val)
{
    return val ? __builtin_ctzll(val) : 64;
}

typedef uint64_t target_ulong;

# define ctztl  ctz64

target_ulong helper_pext(target_ulong src, target_ulong mask)
{
    target_ulong dest = 0;
    int i, o;

    for (o = 0; mask != 0; o++) {
        i = ctztl(mask);
        mask &= mask - 1;
        dest |= ((src >> i) & 1) << o;
    }
    return dest;
}

