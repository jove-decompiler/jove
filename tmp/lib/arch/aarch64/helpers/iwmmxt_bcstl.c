#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_bcstl)(uint32_t arg)
{
    return arg | ((uint64_t) arg << 32);
}

