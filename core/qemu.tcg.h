#pragma once
#ifdef __cplusplus
//
// We shouldn't be using *any* data structures from QEMU whose memory layout
// is altered in some way under a C++ compilation. The CPUArchState, for
// example, is intentionally never referenced directly. If we need to know the
// offset of a particular field, we simply get it from asm-offsets.c.
//
#pragma GCC diagnostic error "-Wc++-compat"

extern "C" {
#endif

#if defined(__x86_64__)
#include "../bin/x86_64/qemu.tcg.copy.h"
#elif defined(__i386__)
#include "../bin/i386/qemu.tcg.copy.h"
#elif defined(__aarch64__)
#include "../bin/aarch64/qemu.tcg.copy.h"
#elif defined(__mips64) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include "../bin/mips64el/qemu.tcg.copy.h"
#elif defined(__mips__) && __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#include "../bin/mipsel/qemu.tcg.copy.h"
#else
#error
#endif

#ifdef __cplusplus
}
#pragma GCC diagnostic pop

#include <type_traits>

namespace jove {
using SignedTCGArg = std::make_signed_t<TCGArg>;
}

#endif /* __cplusplus */
