#include <stdint.h>

uint64_t helper_pmovmskb(uint64_t fs)
{
    unsigned fd = 0;

    fd |= ((fs >>  7) & 1) << 0;
    fd |= ((fs >> 15) & 1) << 1;
    fd |= ((fs >> 23) & 1) << 2;
    fd |= ((fs >> 31) & 1) << 3;
    fd |= ((fs >> 39) & 1) << 4;
    fd |= ((fs >> 47) & 1) << 5;
    fd |= ((fs >> 55) & 1) << 6;
    fd |= ((fs >> 63) & 1) << 7;

    return fd & 0xff;
}

