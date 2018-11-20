#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint32_t HELPER(neon_mul_p8)(uint32_t op1, uint32_t op2)
{
    uint32_t mask;
    uint32_t result;
    result = 0;
    while (op1) {
        mask = 0;
        if (op1 & 1)
            mask |= 0xff;
        if (op1 & (1 << 8))
            mask |= (0xff << 8);
        if (op1 & (1 << 16))
            mask |= (0xff << 16);
        if (op1 & (1 << 24))
            mask |= (0xff << 24);
        result ^= op2 & mask;
        op1 = (op1 >> 1) & 0x7f7f7f7f;
        op2 = (op2 << 1) & 0xfefefefe;
    }
    return result;
}

