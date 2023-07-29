#include <stdint.h>

typedef int64_t target_long;

typedef uint64_t target_ulong;

#define MIPSDSP_HI  0xFFFF0000

#define MIPSDSP_LO  0x0000FFFF

target_ulong helper_packrl_ph(target_ulong rs, target_ulong rt)
{
    uint32_t rsl, rth;

    rsl =  rs & MIPSDSP_LO;
    rth = (rt & MIPSDSP_HI) >> 16;

    return (target_long)(int32_t)((rsl << 16) | rth);
}

