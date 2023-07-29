#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define EXTEND16S(a)    ((int32_t) (int16_t) (a))

#define EXTEND32(a)     ((uint64_t) (int32_t) (a))

uint64_t HELPER(iwmmxt_muladdsw)(uint64_t c, uint32_t a, uint32_t b)
{
    c += EXTEND32(EXTEND16S((a >> 0) & 0xffff) *
                  EXTEND16S((b >> 0) & 0xffff));
    c += EXTEND32(EXTEND16S((a >> 16) & 0xffff) *
                  EXTEND16S((b >> 16) & 0xffff));
    return c;
}

