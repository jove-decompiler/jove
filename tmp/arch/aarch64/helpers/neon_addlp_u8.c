#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_addlp_u8)(uint64_t a)
{
    uint64_t tmp;

    tmp = a & 0x00ff00ff00ff00ffULL;
    tmp += (a >> 8) & 0x00ff00ff00ff00ffULL;
    return tmp;
}

