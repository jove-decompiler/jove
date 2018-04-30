#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_macuw)(uint64_t a, uint64_t b)
{
#define MACU(SHR) ( \
        (uint32_t) ((a >> SHR) & 0xffff) * \
        (uint32_t) ((b >> SHR) & 0xffff))
    return MACU(0) + MACU(16) + MACU(32) + MACU(48);
#undef MACU
}

