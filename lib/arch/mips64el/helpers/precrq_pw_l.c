#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LLO 0x00000000FFFFFFFFull

#define MIPSDSP_RETURN64_32(a, b)       (((uint64_t)(a) << 32) | (uint64_t)(b))

target_ulong helper_precrq_pw_l(target_ulong rs, target_ulong rt)
{
    uint32_t tempB, tempA;

    tempB = (rs >> 32) & MIPSDSP_LLO;
    tempA = (rt >> 32) & MIPSDSP_LLO;

    return MIPSDSP_RETURN64_32(tempB, tempA);
}

