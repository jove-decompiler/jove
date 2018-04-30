#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define DO_ABD(dest, x, y, intype, arithtype) do {            \
    arithtype tmp_x = (intype)(x);                            \
    arithtype tmp_y = (intype)(y);                            \
    dest = ((tmp_x > tmp_y) ? tmp_x - tmp_y : tmp_y - tmp_x); \
    } while(0)

uint64_t HELPER(neon_abdl_s16)(uint32_t a, uint32_t b)
{
    uint64_t tmp;
    uint64_t result;
    DO_ABD(result, a, b, int8_t, int32_t);
    DO_ABD(tmp, a >> 8, b >> 8, int8_t, int32_t);
    result |= tmp << 16;
    DO_ABD(tmp, a >> 16, b >> 16, int8_t, int32_t);
    result |= tmp << 32;
    DO_ABD(tmp, a >> 24, b >> 24, int8_t, int32_t);
    result |= tmp << 48;
    return result;
}

