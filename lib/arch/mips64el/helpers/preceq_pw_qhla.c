#include <stdint.h>

typedef uint64_t target_ulong;

#define MIPSDSP_LO  0x0000FFFF

#define MIPSDSP_RETURN64_32(a, b)       (((uint64_t)(a) << 32) | (uint64_t)(b))

#define PRECEQ_PW(name, a, b) \
target_ulong helper_preceq_pw_##name(target_ulong rt) \
{                                                       \
    uint16_t tempB, tempA;                              \
    uint32_t tempBI, tempAI;                            \
                                                        \
    tempB = (rt >> a) & MIPSDSP_LO;                     \
    tempA = (rt >> b) & MIPSDSP_LO;                     \
                                                        \
    tempBI = (uint32_t)tempB << 16;                     \
    tempAI = (uint32_t)tempA << 16;                     \
                                                        \
    return MIPSDSP_RETURN64_32(tempBI, tempAI);         \
}

PRECEQ_PW(qhla, 48, 16)

