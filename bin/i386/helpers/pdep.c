#include <stdint.h>

static inline int ctz8(uint8_t val)
{
    return val ? __builtin_ctz(val) : 8;
}

static inline int ctz32(uint32_t val)
{
    return val ? __builtin_ctz(val) : 32;
}

typedef uint32_t target_ulong;

# define ctztl  ctz32

target_ulong helper_pdep(target_ulong src, target_ulong mask)
{
    target_ulong dest = 0;
    int i, o;

    for (i = 0; mask != 0; i++) {
        o = ctztl(mask);
        mask &= mask - 1;
        dest |= ((src >> i) & 1) << o;
    }
    return dest;
}

