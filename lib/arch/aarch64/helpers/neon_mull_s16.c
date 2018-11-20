#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define DO_MULL(dest, x, y, type1, type2) do { \
    type1 tmp_x = x; \
    type1 tmp_y = y; \
    dest = (type2)((type2)tmp_x * (type2)tmp_y); \
    } while(0)

uint64_t HELPER(neon_mull_s16)(uint32_t a, uint32_t b)
{
    uint64_t tmp;
    uint64_t result;

    DO_MULL(result, a, b, int16_t, uint32_t);
    DO_MULL(tmp, a >> 16, b >> 16, int16_t, uint32_t);
    return result | (tmp << 32);
}

