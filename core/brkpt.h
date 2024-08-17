#pragma once
#include "jove/jove.h"

namespace jove {

static const uint8_t TargetBrkpt[] = {
#if defined(TARGET_MIPS32) || defined(TARGET_MIPS64)
#ifdef TARGET_WORDS_BIGENDIAN
    0x8c, 0x01, 0x00, 0x00, /* lw at,0(zero) */
#else
    0x00, 0x00, 0x01, 0x8c, /* lw at,0(zero) */
#endif
#elif defined(TARGET_X86_64) || defined(TARGET_I386)
    0x0f, 0x0b /* ud2 */
#elif defined(TARGET_AARCH64)
    0x00, 0x00, 0x00, 0x00 /* udf #0 */
#else
#error
#endif
};

constexpr unsigned TargetBrkptLen = ARRAY_SIZE(TargetBrkpt);

}
