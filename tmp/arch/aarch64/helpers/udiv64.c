#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(udiv64)(uint64_t num, uint64_t den)
{
    if (den == 0) {
        return 0;
    }
    return num / den;
}

