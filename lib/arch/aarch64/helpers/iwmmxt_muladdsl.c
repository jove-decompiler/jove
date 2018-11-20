#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

#define EXTEND32(a)	((uint64_t) (int32_t) (a))

uint64_t HELPER(iwmmxt_muladdsl)(uint64_t c, uint32_t a, uint32_t b)
{
    return c + ((int32_t) EXTEND32(a) * (int32_t) EXTEND32(b));
}

