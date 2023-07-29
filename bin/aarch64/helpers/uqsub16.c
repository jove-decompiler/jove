#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

static inline uint16_t sub16_usat(uint16_t a, uint16_t b)
{
    if (a > b) {
        return a - b;
    } else {
        return 0;
    }
}

#define SUB16(a, b, n) RESULT(sub16_usat(a, b), n, 16);

#define PFX uq

#define GE_ARG

#define DECLARE_GE do{}while(0)

#define SET_GE do{}while(0)

#define RESULT(val, n, width) \
    res |= ((uint32_t)(glue(glue(uint,width),_t))(val)) << (n * width)

uint32_t HELPER(glue(PFX,sub16))(uint32_t a, uint32_t b GE_ARG)
{
    uint32_t res = 0;
    DECLARE_GE;

    SUB16(a, b, 0);
    SUB16(a >> 16, b >> 16, 1);
    SET_GE;
    return res;
}

