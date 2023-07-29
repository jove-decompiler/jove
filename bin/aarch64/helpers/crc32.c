#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define le_bswap(v, size) (v)

static inline int lduw_he_p(const void *ptr)
{
    uint16_t r;
    __builtin_memcpy(&r, ptr, sizeof(r));
    return r;
}

static inline void stl_he_p(void *ptr, uint32_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}

static inline void stl_le_p(void *ptr, uint32_t v)
{
    stl_he_p(ptr, le_bswap(v, 32));
}

#define HELPER(name) glue(helper_, name)

#if 0
#include <zlib.h>
#else
unsigned long crc32(unsigned long _crc, const void * buf, unsigned len);
#endif

uint32_t HELPER(crc32)(uint32_t acc, uint32_t val, uint32_t bytes)
{
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* zlib crc32 converts the accumulator and output to one's complement.  */
    return crc32(acc ^ 0xffffffff, buf, bytes) ^ 0xffffffff;
}

