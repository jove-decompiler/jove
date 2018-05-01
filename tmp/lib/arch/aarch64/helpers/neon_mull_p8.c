#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_mull_p8)(uint32_t op1, uint32_t op2)
{
    uint64_t result = 0;
    uint64_t mask;
    uint64_t op2ex = op2;
    op2ex = (op2ex & 0xff) |
        ((op2ex & 0xff00) << 8) |
        ((op2ex & 0xff0000) << 16) |
        ((op2ex & 0xff000000) << 24);
    while (op1) {
        mask = 0;
        if (op1 & 1) {
            mask |= 0xffff;
        }
        if (op1 & (1 << 8)) {
            mask |= (0xffffU << 16);
        }
        if (op1 & (1 << 16)) {
            mask |= (0xffffULL << 32);
        }
        if (op1 & (1 << 24)) {
            mask |= (0xffffULL << 48);
        }
        result ^= op2ex & mask;
        op1 = (op1 >> 1) & 0x7f7f7f7f;
        op2ex <<= 1;
    }
    return result;
}

