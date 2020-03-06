#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

void mulu64(uint64_t *phigh, uint64_t *plow, uint64_t a, uint64_t b);

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(muluh_i64)(uint64_t arg1, uint64_t arg2)
{
    uint64_t l, h;
    mulu64(&l, &h, arg1, arg2);
    return h;
}

