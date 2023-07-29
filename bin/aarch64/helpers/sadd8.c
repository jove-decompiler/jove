#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define SARITH8(a, b, n, op) do { \
    int32_t sum; \
    sum = (int32_t)(int8_t)(a) op (int32_t)(int8_t)(b); \
    RESULT(sum, n, 8); \
    if (sum >= 0) \
        ge |= 1 << n; \
    } while (0)

#define ADD8(a, b, n)  SARITH8(a, b, n, +)

#define PFX s

#define GE_ARG , void *gep

#define DECLARE_GE uint32_t ge = 0

#define SET_GE *(uint32_t *)gep = ge

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

