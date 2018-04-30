#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_addcl)(uint64_t x)
{
    return (x & 0xffffffff) + (x >> 32);
}

