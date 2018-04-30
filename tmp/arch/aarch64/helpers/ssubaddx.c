#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define SARITH16(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int16_t)(a) op (int32_t)(int16_t)(b); \
    RESULT(sum, n, 16); \
    if (sum >= 0) \
        ge |= 3 << (n * 2); \
    } while(0)

#define ADD16(a, b, n) SARITH16(a, b, n, +)

#define SUB16(a, b, n) SARITH16(a, b, n, -)

#define PFX s

#define GE_ARG , void *gep

#define DECLARE_GE uint32_t ge = 0

#define SET_GE *(uint32_t *)gep = ge

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

