#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <sys/types.h>

#include <byteswap.h>

static inline uint16_t bswap16(uint16_t x)
{
    return bswap_16(x);
}

static inline uint64_t bswap64(uint64_t x)
{
    return bswap_64(x);
}

static inline uint64_t revbit64(uint64_t x)
{
    /* Assign the correct byte position.  */
    x = bswap64(x);
    /* Assign the correct nibble position.  */
    x = ((x & 0xf0f0f0f0f0f0f0f0ull) >> 4)
      | ((x & 0x0f0f0f0f0f0f0f0full) << 4);
    /* Assign the correct bit position.  */
    x = ((x & 0x8888888888888888ull) >> 3)
      | ((x & 0x4444444444444444ull) >> 1)
      | ((x & 0x2222222222222222ull) << 1)
      | ((x & 0x1111111111111111ull) << 3);
    return x;
}

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(rbit64)(uint64_t x)
{
    return revbit64(x);
}

