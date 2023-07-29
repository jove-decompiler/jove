#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define DO_MULL(dest, x, y, type1, type2) do { \
    type1 tmp_x = x; \
    type1 tmp_y = y; \
    dest = (type2)((type2)tmp_x * (type2)tmp_y); \
    } while(0)

uint64_t HELPER(neon_mull_u8)(uint32_t a, uint32_t b)
{
    uint64_t tmp;
    uint64_t result;

    DO_MULL(result, a, b, uint8_t, uint16_t);
    DO_MULL(tmp, a >> 8, b >> 8, uint8_t, uint16_t);
    result |= tmp << 16;
    DO_MULL(tmp, a >> 16, b >> 16, uint8_t, uint16_t);
    result |= tmp << 32;
    DO_MULL(tmp, a >> 24, b >> 24, uint8_t, uint16_t);
    result |= tmp << 48;
    return result;
}

