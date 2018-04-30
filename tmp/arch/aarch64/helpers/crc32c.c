#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stddef.h>

#include <stdint.h>

#include <string.h>

#define le_bswap(v, size) (v)

static inline void stl_he_p(void *ptr, uint32_t v)
{
    memcpy(ptr, &v, sizeof(v));
}

static inline void stl_le_p(void *ptr, uint32_t v)
{
    stl_he_p(ptr, le_bswap(v, 32));
}

#define HELPER(name) glue(helper_, name)

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);

uint32_t HELPER(crc32c)(uint32_t acc, uint32_t val, uint32_t bytes)
{
    uint8_t buf[4];

    stl_le_p(buf, val);

    /* Linux crc32c converts the output to one's complement.  */
    return crc32c(acc, buf, bytes) ^ 0xffffffff;
}

