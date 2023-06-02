#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

target_ulong helper_bitrev(target_ulong rt)
{
    int32_t temp;
    uint32_t rd;
    int i;

    temp = rt & MIPSDSP_LO;
    rd = 0;
    for (i = 0; i < 16; i++) {
        rd = (rd << 1) | (temp & 1);
        temp = temp >> 1;
    }

    return (target_ulong)rd;
}

