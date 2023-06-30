#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

static inline uint16_t add16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a + b;
    if (((res ^ a) & 0x8000) && !((a ^ b) & 0x8000)) {
        if (a & 0x8000) {
            res = 0x8000;
        } else {
            res = 0x7fff;
        }
    }
    return res;
}

static inline uint16_t sub16_sat(uint16_t a, uint16_t b)
{
    uint16_t res;

    res = a - b;
    if (((res ^ a) & 0x8000) && ((a ^ b) & 0x8000)) {
        if (a & 0x8000) {
            res = 0x8000;
        } else {
            res = 0x7fff;
        }
    }
    return res;
}

#define ADD16(a, b, n) RESULT(add16_sat(a, b), n, 16);

#define SUB16(a, b, n) RESULT(sub16_sat(a, b), n, 16);

#define PFX q

#define GE_ARG

#define DECLARE_GE do{}while(0)

#define SET_GE do{}while(0)

#define RESULT(val, n, width) \
    res |= ((uint32_t)(glue(glue(uint,width),_t))(val)) << (n * width)

uint32_t HELPER(glue(PFX,subaddx))(uint32_t a, uint32_t b GE_ARG)
{
    uint32_t res = 0;
    DECLARE_GE;

    ADD16(a, b >> 16, 0);
    SUB16(a >> 16, b, 1);
    SET_GE;
    return res;
}

