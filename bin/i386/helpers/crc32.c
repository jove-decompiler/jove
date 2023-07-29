#include <stdint.h>

# define TARGET_LONG_BITS             32

typedef uint32_t target_ulong;

#define CRCPOLY_BITREV 0x82f63b78

target_ulong helper_crc32(uint32_t crc1, target_ulong msg, uint32_t len)
{
    target_ulong crc = (msg & ((target_ulong) -1 >>
                               (TARGET_LONG_BITS - len))) ^ crc1;

    while (len--) {
        crc = (crc >> 1) ^ ((crc & 1) ? CRCPOLY_BITREV : 0);
    }

    return crc;
}

