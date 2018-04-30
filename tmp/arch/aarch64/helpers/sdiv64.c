#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#include <limits.h>

#define HELPER(name) glue(helper_, name)

int64_t HELPER(sdiv64)(int64_t num, int64_t den)
{
    if (den == 0) {
        return 0;
    }
    if (num == LLONG_MIN && den == -1) {
        return LLONG_MIN;
    }
    return num / den;
}

