#include <stdint.h>

#define SATSB(x)  (x < -0x80 ? -0x80 : x > 0x7f ? 0x7f : x)

uint64_t helper_packsshb(uint64_t fs, uint64_t ft)
{
    uint64_t fd = 0;
    unsigned int i;

    for (i = 0; i < 4; ++i) {
        int16_t tmp = fs >> (i * 16);
        tmp = SATSB(tmp);
        fd |= (uint64_t)(tmp & 0xff) << (i * 8);
    }
    for (i = 0; i < 4; ++i) {
        int16_t tmp = ft >> (i * 16);
        tmp = SATSB(tmp);
        fd |= (uint64_t)(tmp & 0xff) << (i * 8 + 32);
    }

    return fd;
}

