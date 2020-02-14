#include <stdint.h>

uint64_t helper_punpckhwd(uint64_t fs, uint64_t ft)
{
    return (fs >> 32) | (ft & ~0xffffffffull);
}

