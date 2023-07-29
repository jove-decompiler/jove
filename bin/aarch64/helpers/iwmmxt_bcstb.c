#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_bcstb)(uint32_t arg)
{
    arg &= 0xff;
    return
        ((uint64_t) arg << 0 ) | ((uint64_t) arg << 8 ) |
        ((uint64_t) arg << 16) | ((uint64_t) arg << 24) |
        ((uint64_t) arg << 32) | ((uint64_t) arg << 40) |
        ((uint64_t) arg << 48) | ((uint64_t) arg << 56);
}

