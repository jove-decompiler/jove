#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define EXTEND16S(a)    ((int32_t) (int16_t) (a))

uint64_t HELPER(iwmmxt_mulshw)(uint64_t a, uint64_t b)
{
#define MULS(SHR) ((uint64_t) ((( \
        EXTEND16S((a >> SHR) & 0xffff) * EXTEND16S((b >> SHR) & 0xffff) \
    ) >> 16) & 0xffff) << SHR)
    return MULS(0) | MULS(16) | MULS(32) | MULS(48);
#undef MULS
}

