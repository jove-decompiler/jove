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

static inline void stq_he_p(void *ptr, uint64_t v)
{
    __builtin_memcpy(ptr, &v, sizeof(v));
}

static inline void stq_le_p(void *ptr, uint64_t v)
{
    stq_he_p(ptr, le_bswap(v, 64));
}

#define HELPER(name) glue(helper_, name)

uint32_t crc32c(uint32_t crc, const uint8_t *data, unsigned int length);

uint64_t HELPER(crc32c_64)(uint64_t acc, uint64_t val, uint32_t bytes)
{
    uint8_t buf[8];

    stq_le_p(buf, val);

    /* Linux crc32c converts the output to one's complement.  */
    return crc32c(acc, buf, bytes) ^ 0xffffffff;
}

