#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_addcw)(uint64_t x)
{
    return
        ((x >> 0) & 0xffff) + ((x >> 16) & 0xffff) +
        ((x >> 32) & 0xffff) + ((x >> 48) & 0xffff);
}

