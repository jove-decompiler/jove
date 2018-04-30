#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(iwmmxt_mululw)(uint64_t a, uint64_t b)
{
#define MULU(SHR) ((uint64_t) ((( \
        ((a >> SHR) & 0xffff) * ((b >> SHR) & 0xffff) \
    ) >> 0) & 0xffff) << SHR)
    return MULU(0) | MULU(16) | MULU(32) | MULU(48);
#undef MULU
}

