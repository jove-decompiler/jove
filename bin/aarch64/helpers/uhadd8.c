#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define ADD8(a, b, n) \
  RESULT(((uint32_t)(uint8_t)(a) + (uint32_t)(uint8_t)(b)) >> 1, n, 8)

#define PFX uh

#define GE_ARG

#define DECLARE_GE do{}while(0)

#define SET_GE do{}while(0)

#define RESULT(val, n, width) \
    res |= ((uint32_t)(glue(glue(uint,width),_t))(val)) << (n * width)

uint32_t HELPER(glue(PFX,add8))(uint32_t a, uint32_t b GE_ARG)
{
    uint32_t res = 0;
    DECLARE_GE;

    ADD8(a, b, 0);
    ADD8(a >> 8, b >> 8, 1);
    ADD8(a >> 16, b >> 16, 2);
    ADD8(a >> 24, b >> 24, 3);
    SET_GE;
    return res;
}

