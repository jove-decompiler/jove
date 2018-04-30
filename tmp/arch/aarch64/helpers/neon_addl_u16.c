#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_addl_u16)(uint64_t a, uint64_t b)
{
    uint64_t mask;
    mask = (a ^ b) & 0x8000800080008000ull;
    a &= ~0x8000800080008000ull;
    b &= ~0x8000800080008000ull;
    return (a + b) ^ mask;
}

