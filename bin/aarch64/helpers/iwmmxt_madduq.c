#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_madduq)(uint64_t a, uint64_t b)
{
    a = ((
            ((a >> 0) & 0xffff) * ((b >> 0) & 0xffff) +
            ((a >> 16) & 0xffff) * ((b >> 16) & 0xffff)
        ) & 0xffffffff) | ((
            ((a >> 32) & 0xffff) * ((b >> 32) & 0xffff) +
            ((a >> 48) & 0xffff) * ((b >> 48) & 0xffff)
        ) << 32);
    return a;
}

