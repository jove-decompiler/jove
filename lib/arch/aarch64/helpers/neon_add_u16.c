#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_add_u16)(uint32_t a, uint32_t b)
{
    uint32_t mask;
    mask = (a ^ b) & 0x80008000u;
    a &= ~0x80008000u;
    b &= ~0x80008000u;
    return (a + b) ^ mask;
}

