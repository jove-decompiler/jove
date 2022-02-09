#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

void muls64(uint64_t *phigh, uint64_t *plow, int64_t a, int64_t b);

#define HELPER(name) glue(helper_, name)

int64_t HELPER(mulsh_i64)(int64_t arg1, int64_t arg2)
{
    uint64_t l, h;
    muls64(&l, &h, arg1, arg2);
    return h;
}

