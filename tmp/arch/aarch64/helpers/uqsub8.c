#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define SUB8(a, b, n)  RESULT(sub8_usat(a, b), n, 8);

#define PFX uq

#define GE_ARG

#define DECLARE_GE do{}while(0)

#define SET_GE do{}while(0)

#define RESULT(val, n, width) \
    res |= ((uint32_t)(glue(glue(uint,width),_t))(val)) << (n * width)

static inline uint8_t sub8_usat(uint8_t a, uint8_t b)
{
    if (a > b)
        return a - b;
    else
        return 0;
}

uint32_t HELPER(glue(PFX,sub8))(uint32_t a, uint32_t b GE_ARG)
{
    uint32_t res = 0;
    DECLARE_GE;

    SUB8(a, b, 0);
    SUB8(a >> 8, b >> 8, 1);
    SUB8(a >> 16, b >> 16, 2);
    SUB8(a >> 24, b >> 24, 3);
    SET_GE;
    return res;
}

