#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_pmull_64_hi)(uint64_t op1, uint64_t op2)
{
    int bitnum;
    uint64_t res = 0;

    /* bit 0 of op1 can't influence the high 64 bits at all */
    for (bitnum = 1; bitnum < 64; bitnum++) {
        if (op1 & (1ULL << bitnum)) {
            res ^= op2 >> (64 - bitnum);
        }
    }
    return res;
}

