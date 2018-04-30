#define xglue(x, y) x ## y

#define glue(x, y) xglue(x, y)

#include <stdint.h>

#define HELPER(name) glue(helper_, name)

uint64_t HELPER(neon_addlp_s8)(uint64_t a)
{
    uint64_t nsignmask = 0x0080008000800080ULL;
    uint64_t wsignmask = 0x8000800080008000ULL;
    uint64_t elementmask = 0x00ff00ff00ff00ffULL;
    uint64_t tmp1, tmp2;
    uint64_t res, signres;

    /* Extract odd elements, sign extend each to a 16 bit field */
    tmp1 = a & elementmask;
    tmp1 ^= nsignmask;
    tmp1 |= wsignmask;
    tmp1 = (tmp1 - nsignmask) ^ wsignmask;
    /* Ditto for the even elements */
    tmp2 = (a >> 8) & elementmask;
    tmp2 ^= nsignmask;
    tmp2 |= wsignmask;
    tmp2 = (tmp2 - nsignmask) ^ wsignmask;

    /* calculate the result by summing bits 0..14, 16..22, etc,
     * and then adjusting the sign bits 15, 23, etc manually.
     * This ensures the addition can't overflow the 16 bit field.
     */
    signres = (tmp1 ^ tmp2) & wsignmask;
    res = (tmp1 & ~wsignmask) + (tmp2 & ~wsignmask);
    res ^= signres;

    return res;
}

