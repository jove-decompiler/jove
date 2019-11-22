#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define EXTEND16S(a)    ((int32_t) (int16_t) (a))

uint64_t HELPER(iwmmxt_maddsq)(uint64_t a, uint64_t b)
{
    a = ((
            EXTEND16S((a >> 0) & 0xffff) * EXTEND16S((b >> 0) & 0xffff) +
            EXTEND16S((a >> 16) & 0xffff) * EXTEND16S((b >> 16) & 0xffff)
        ) & 0xffffffff) | ((uint64_t) (
            EXTEND16S((a >> 32) & 0xffff) * EXTEND16S((b >> 32) & 0xffff) +
            EXTEND16S((a >> 48) & 0xffff) * EXTEND16S((b >> 48) & 0xffff)
        ) << 32);
    return a;
}

