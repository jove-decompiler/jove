#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(remu_i32)(uint32_t arg1, uint32_t arg2)
{
    return arg1 % arg2;
}

