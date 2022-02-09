#include <stdint.h>

#define SATUB(x)  (x > 0xff ? 0xff : x)

uint64_t helper_packushb(uint64_t fs, uint64_t ft)
{
    uint64_t fd = 0;
    unsigned int i;

    for (i = 0; i < 4; ++i) {
        int16_t tmp = fs >> (i * 16);
        tmp = SATUB(tmp);
        fd |= (uint64_t)(tmp & 0xff) << (i * 8);
    }
    for (i = 0; i < 4; ++i) {
        int16_t tmp = ft >> (i * 16);
        tmp = SATUB(tmp);
        fd |= (uint64_t)(tmp & 0xff) << (i * 8 + 32);
    }

    return fd;
}

