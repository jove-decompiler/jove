#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(remu_i64)(uint64_t arg1, uint64_t arg2)
{
    return arg1 % arg2;
}

