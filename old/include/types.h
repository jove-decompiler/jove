#pragma once
#include <config-target.h>
#include <cstdint>

namespace jove {
#if defined(TARGET_AARCH64) || defined(TARGET_X86_64) || defined(TARGET_MIPS64)
typedef uint64_t address_t;
#else
typedef uint32_t address_t;
#endif
}
