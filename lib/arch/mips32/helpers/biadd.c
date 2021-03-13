#include <stdint.h>

__attribute__((always_inline))
uint64_t helper_biadd(uint64_t fs)
{
    unsigned i, fd;

    for (i = fd = 0; i < 8; ++i) {
        fd += (fs >> (i * 8)) & 0xff;
    }
    return fd & 0xffff;
}

