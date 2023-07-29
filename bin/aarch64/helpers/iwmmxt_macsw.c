#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define EXTEND16(a)     ((uint32_t) (int16_t) (a))

#define EXTEND16S(a)    ((int32_t) (int16_t) (a))

uint64_t HELPER(iwmmxt_macsw)(uint64_t a, uint64_t b)
{
#define MACS(SHR) ( \
        EXTEND16((a >> SHR) & 0xffff) * EXTEND16S((b >> SHR) & 0xffff))
    return (int64_t) (MACS(0) + MACS(16) + MACS(32) + MACS(48));
#undef MACS
}

