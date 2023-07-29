#include <stdint.h>

#define SATSH(x)  (x < -0x8000 ? -0x8000 : x > 0x7fff ? 0x7fff : x)

uint64_t helper_packsswh(uint64_t fs, uint64_t ft)
{
    uint64_t fd = 0;
    int64_t tmp;

    tmp = (int32_t)(fs >> 0);
    tmp = SATSH(tmp);
    fd |= (tmp & 0xffff) << 0;

    tmp = (int32_t)(fs >> 32);
    tmp = SATSH(tmp);
    fd |= (tmp & 0xffff) << 16;

    tmp = (int32_t)(ft >> 0);
    tmp = SATSH(tmp);
    fd |= (tmp & 0xffff) << 32;

    tmp = (int32_t)(ft >> 32);
    tmp = SATSH(tmp);
    fd |= (tmp & 0xffff) << 48;

    return fd;
}

