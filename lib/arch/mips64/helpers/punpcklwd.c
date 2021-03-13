#include <stdint.h>

uint64_t helper_punpcklwd(uint64_t fs, uint64_t ft)
{
    return (fs & 0xffffffff) | (ft << 32);
}

