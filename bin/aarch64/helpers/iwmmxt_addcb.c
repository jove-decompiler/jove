#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_addcb)(uint64_t x)
{
    return
        ((x >> 0) & 0xff) + ((x >> 8) & 0xff) +
        ((x >> 16) & 0xff) + ((x >> 24) & 0xff) +
        ((x >> 32) & 0xff) + ((x >> 40) & 0xff) +
        ((x >> 48) & 0xff) + ((x >> 56) & 0xff);
}

